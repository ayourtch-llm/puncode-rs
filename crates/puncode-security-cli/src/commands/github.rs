//! Listing an owner's repositories from GitHub.
//!
//! Ported from the Octokit half of `src/bulk-scan-discovery.ts`.
//!
//! Credentials come from the GitHub CLI rather than from anything this program
//! stores or asks for: `gh` already holds the user's sign-in, and asking again
//! would mean handling a token this program has no reason to keep.
//!
//! The HTTP itself sits behind [`GitHubTransport`] so the query, the paging and
//! the shape of what comes back can be checked without a network.

use puncode_security::bulk_scan_discovery::{RepositoryNode, RepositoryPage, RepositorySource};
use puncode_security::targets::ProcessEnvironment;
use serde_json::{Value, json};

/// The repositories worth listing: not archived, not forks, newest first.
///
/// Ordering by push date is what lets discovery stop early rather than page
/// through years of dormant repositories.
const REPOSITORIES_QUERY: &str = r"
  query($owner: String!, $cursor: String) {
    repositoryOwner(login: $owner) {
      repositories(
        first: 100
        after: $cursor
        isArchived: false
        isFork: false
        orderBy: { field: PUSHED_AT, direction: DESC }
      ) {
        nodes {
          nameWithOwner
          pushedAt
          defaultBranchRef { target { oid } }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
";

/// Talks to one GitHub instance.
pub trait GitHubTransport {
    /// Runs a GraphQL query.
    fn graphql(&self, query: &str, variables: Value) -> Result<Value, String>;

    /// Reads a REST endpoint, such as `/user/orgs`.
    fn get(&self, path: &str) -> Result<Value, String>;
}

/// Lists repositories from GitHub.
pub struct GitHubSource<T> {
    transport: T,
}

impl<T: GitHubTransport> GitHubSource<T> {
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self { transport }
    }
}

impl<T: GitHubTransport> RepositorySource for GitHubSource<T> {
    fn organizations(&self) -> puncode_security::Result<Vec<String>> {
        let response = self
            .transport
            .get("/user/orgs?per_page=100")
            .map_err(puncode_security::Error::puncode_security)?;
        let mut names: Vec<String> = response
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.get("login").and_then(Value::as_str))
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        // Sorted so the choice is presented the same way twice running.
        names.sort();
        Ok(names)
    }

    fn signed_in_account(&self) -> puncode_security::Result<String> {
        self.transport
            .get("/user")
            .map_err(puncode_security::Error::puncode_security)?
            .get("login")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| {
                puncode_security::Error::puncode_security(
                    "GitHub did not report a signed-in account.",
                )
            })
    }

    fn repositories(
        &self,
        owner: &str,
        cursor: Option<&str>,
    ) -> puncode_security::Result<RepositoryPage> {
        let response = self
            .transport
            .graphql(
                REPOSITORIES_QUERY,
                json!({ "owner": owner, "cursor": cursor }),
            )
            .map_err(puncode_security::Error::puncode_security)?;

        let connection = response
            .get("data")
            .and_then(|data| data.get("repositoryOwner"))
            .filter(|owner| !owner.is_null())
            .and_then(|owner| owner.get("repositories"))
            .ok_or_else(|| {
                puncode_security::Error::puncode_security(
                    "GitHub could not list repositories for this account.",
                )
            })?;

        let nodes = connection
            .get("nodes")
            .and_then(Value::as_array)
            .map(|nodes| {
                nodes
                    .iter()
                    .filter_map(|node| {
                        Some(RepositoryNode {
                            name_with_owner: node.get("nameWithOwner")?.as_str()?.to_owned(),
                            pushed_at: node.get("pushedAt")?.as_str()?.to_owned(),
                            // Absent when the repository has no commits.
                            default_branch_oid: node
                                .get("defaultBranchRef")
                                .and_then(|reference| reference.get("target"))
                                .and_then(|target| target.get("oid"))
                                .and_then(Value::as_str)
                                .map(str::to_owned),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let page = connection.get("pageInfo");
        let end_cursor = page
            .filter(|page| {
                page.get("hasNextPage")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            })
            .and_then(|page| page.get("endCursor"))
            .and_then(Value::as_str)
            .map(str::to_owned);

        Ok(RepositoryPage { nodes, end_cursor })
    }
}

/// Talks to GitHub over HTTPS.
pub struct HttpTransport {
    token: String,
    /// Where GraphQL queries are posted.
    graphql_url: String,
    /// What REST paths are joined onto.
    rest_base: String,
}

impl HttpTransport {
    /// Builds a transport for `host`, taking the credential from `gh`.
    pub fn new(host: &str, environment: &ProcessEnvironment) -> Result<Self, String> {
        let token = github_token(host, environment)?;
        // Enterprise instances serve the API beneath `/api/v3`, as Octokit's
        // `baseUrl` does.
        let (graphql_url, rest_base) = if host == "github.com" {
            (
                "https://api.github.com/graphql".to_owned(),
                "https://api.github.com".to_owned(),
            )
        } else {
            (
                format!("https://{host}/api/v3/graphql"),
                format!("https://{host}/api/v3"),
            )
        };
        Ok(Self {
            token,
            graphql_url,
            rest_base,
        })
    }
}

impl GitHubTransport for HttpTransport {
    fn graphql(&self, query: &str, variables: Value) -> Result<Value, String> {
        let response: Value = ureq::post(&self.graphql_url)
            .header("Authorization", &format!("Bearer {}", self.token))
            .header("Accept", "application/vnd.github+json")
            .send_json(json!({ "query": query, "variables": variables }))
            .map_err(|error| format!("GitHub request failed: {error}"))?
            .body_mut()
            .read_json()
            .map_err(|error| format!("GitHub returned an unreadable response: {error}"))?;

        // GraphQL reports failures in the body rather than the status.
        if let Some(problem) = response
            .get("errors")
            .and_then(Value::as_array)
            .and_then(|errors| errors.first())
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str)
        {
            return Err(format!("GitHub rejected the query: {problem}"));
        }
        Ok(response)
    }

    fn get(&self, path: &str) -> Result<Value, String> {
        ureq::get(&format!("{}{path}", self.rest_base))
            .header("Authorization", &format!("Bearer {}", self.token))
            .header("Accept", "application/vnd.github+json")
            .call()
            .map_err(|error| format!("GitHub request failed: {error}"))?
            .body_mut()
            .read_json()
            .map_err(|error| format!("GitHub returned an unreadable response: {error}"))
    }
}

/// The credential `gh` already holds for `host`.
///
/// Resolved through the trusted search, so a `gh` sitting in the working
/// directory is never the one that runs.
fn github_token(host: &str, environment: &ProcessEnvironment) -> Result<String, String> {
    let protected_root = std::env::current_dir().unwrap_or_else(|_| ".".into());
    let command = puncode_security::trusted_executable::resolve_trusted_executable(
        "gh",
        environment,
        &protected_root,
    )
    .ok_or_else(|| "GitHub CLI is required. Install gh and sign in first.".to_owned())?;

    let output = std::process::Command::new(&command.executable)
        .args(["auth", "token", "--hostname", host])
        .env_clear()
        .envs(&command.environment)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|_| "GitHub sign-in is required. Run 'gh auth login' first.".to_owned())?;

    if !output.status.success() {
        return Err("GitHub sign-in is required. Run 'gh auth login' first.".to_owned());
    }
    let token = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if token.is_empty() {
        return Err("GitHub sign-in is required. Run 'gh auth login' first.".to_owned());
    }
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// A transport that answers with prepared responses.
    struct FakeTransport {
        graphql: RefCell<Vec<Value>>,
        rest: RefCell<std::collections::BTreeMap<String, Value>>,
        queries: RefCell<Vec<Value>>,
    }

    impl FakeTransport {
        fn new(pages: Vec<Value>) -> Self {
            Self {
                graphql: RefCell::new(pages),
                rest: RefCell::new(std::collections::BTreeMap::new()),
                queries: RefCell::new(Vec::new()),
            }
        }

        fn answering(path: &str, value: Value) -> Self {
            let transport = Self::new(Vec::new());
            transport.rest.borrow_mut().insert(path.to_owned(), value);
            transport
        }
    }

    impl GitHubTransport for FakeTransport {
        fn graphql(&self, _query: &str, variables: Value) -> Result<Value, String> {
            self.queries.borrow_mut().push(variables);
            let mut pages = self.graphql.borrow_mut();
            if pages.is_empty() {
                return Err("no more pages".to_owned());
            }
            Ok(pages.remove(0))
        }

        fn get(&self, path: &str) -> Result<Value, String> {
            self.rest
                .borrow()
                .get(path)
                .cloned()
                .ok_or_else(|| format!("unexpected request: {path}"))
        }
    }

    /// One page of the GraphQL response GitHub returns.
    fn page(nodes: Value, next: Option<&str>) -> Value {
        json!({
            "data": { "repositoryOwner": { "repositories": {
                "nodes": nodes,
                "pageInfo": {
                    "hasNextPage": next.is_some(),
                    "endCursor": next,
                },
            }}}
        })
    }

    fn node(name: &str, pushed: &str, oid: Option<&str>) -> Value {
        json!({
            "nameWithOwner": name,
            "pushedAt": pushed,
            "defaultBranchRef": oid.map(|oid| json!({ "target": { "oid": oid } })),
        })
    }

    #[test]
    fn reads_a_page_of_repositories() {
        let transport = FakeTransport::new(vec![page(
            json!([node("acme/payments", "2026-07-01T00:00:00Z", Some("abc"))]),
            None,
        )]);
        let source = GitHubSource::new(transport);

        let result = source.repositories("acme", None).expect("a page");

        assert_eq!(result.nodes.len(), 1);
        assert_eq!(result.nodes[0].name_with_owner, "acme/payments");
        assert_eq!(result.nodes[0].default_branch_oid.as_deref(), Some("abc"));
        assert_eq!(result.end_cursor, None);
    }

    // A repository with no commits has no default branch.
    #[test]
    fn reads_a_repository_with_no_commits() {
        let transport = FakeTransport::new(vec![page(
            json!([node("acme/empty", "2026-07-01T00:00:00Z", None)]),
            None,
        )]);
        let source = GitHubSource::new(transport);

        let result = source.repositories("acme", None).expect("a page");

        assert_eq!(result.nodes[0].default_branch_oid, None);
    }

    // The cursor is only reported when there is another page, so discovery
    // stops rather than asking for one that is not there.
    #[test]
    fn reports_a_cursor_only_when_another_page_follows() {
        let with_more = FakeTransport::new(vec![page(json!([]), Some("cursor-1"))]);
        let without = FakeTransport::new(vec![json!({
            "data": { "repositoryOwner": { "repositories": {
                "nodes": [],
                "pageInfo": { "hasNextPage": false, "endCursor": "cursor-1" },
            }}}
        })]);

        assert_eq!(
            GitHubSource::new(with_more)
                .repositories("acme", None)
                .expect("a page")
                .end_cursor
                .as_deref(),
            Some("cursor-1")
        );
        assert_eq!(
            GitHubSource::new(without)
                .repositories("acme", None)
                .expect("a page")
                .end_cursor,
            None,
            "a stale cursor must not be followed"
        );
    }

    #[test]
    fn passes_the_owner_and_cursor_to_the_query() {
        let transport = FakeTransport::new(vec![page(json!([]), None)]);
        let source = GitHubSource::new(transport);

        source
            .repositories("acme", Some("cursor-1"))
            .expect("a page");

        let queries = source.transport.queries.borrow();
        assert_eq!(queries[0]["owner"], "acme");
        assert_eq!(queries[0]["cursor"], "cursor-1");
    }

    // An account the credential cannot see comes back as a null owner, which
    // is a failure rather than an empty list.
    #[test]
    fn refuses_an_owner_it_cannot_see() {
        let transport = FakeTransport::new(vec![json!({ "data": { "repositoryOwner": null } })]);
        let source = GitHubSource::new(transport);

        let error = source.repositories("acme", None).expect_err("refused");

        assert!(
            error.to_string().contains("could not list repositories"),
            "{error}"
        );
    }

    #[test]
    fn lists_organizations_in_a_stable_order() {
        let transport = FakeTransport::answering(
            "/user/orgs?per_page=100",
            json!([{ "login": "zeta" }, { "login": "acme" }]),
        );
        let source = GitHubSource::new(transport);

        assert_eq!(source.organizations().expect("orgs"), ["acme", "zeta"]);
    }

    // A personal account belonging to no organization is still something to
    // scan, so an empty list is not the end of the search.
    #[test]
    fn reports_the_signed_in_account() {
        let transport = FakeTransport::answering("/user", json!({ "login": "someone" }));
        let source = GitHubSource::new(transport);

        assert_eq!(source.signed_in_account().expect("account"), "someone");
    }
}
