//! Error types for the Codex Security SDK.
//!
//! Ported from `src/errors.ts`. Upstream models failures as a class hierarchy
//! and branches on it with `instanceof`; this port keeps a single error type
//! carrying an [`ErrorKind`], and exposes the load-bearing "is-a" relationships
//! as predicates (for example [`Error::is_scan_interrupted`], which is also
//! true for a cost-limit failure).

use std::error::Error as StdError;
use std::fmt;
use std::path::{Path, PathBuf};

use crate::cost::{ScanCost, format_usd};

/// Which scan-owned directory escaped the protected root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProtectedScanPathKind {
    #[default]
    Output,
    Temporary,
    Runtime,
}

impl ProtectedScanPathKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Output => "output",
            Self::Temporary => "temporary",
            Self::Runtime => "runtime",
        }
    }
}

impl fmt::Display for ProtectedScanPathKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The failure category, along with any payload that category carries.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The base `PuncodeSecurityError`, thrown directly upstream.
    PuncodeSecurity,
    Configuration,
    AuthenticationRequired,
    PluginBootstrap,
    PluginPythonUnavailable,
    InvalidTarget,
    OutputDirectory,
    OutputInsideProtectedRoot {
        output_directory: PathBuf,
        protected_root: PathBuf,
        path_kind: ProtectedScanPathKind,
    },
    IncompleteScan,
    ContractValidation,
    ScanInterrupted {
        scan_dir: PathBuf,
    },
    ScanCostLimitExceeded {
        max_cost_usd: f64,
        cost: ScanCost,
        scan_dir: PathBuf,
    },
    /// Several failures raised together; see [`Error::aggregate`].
    Aggregate,
}

/// A Codex Security failure.
#[derive(Debug)]
pub struct Error {
    kind: Box<ErrorKind>,
    message: String,
    source: Option<Box<dyn StdError + Send + Sync>>,
    /// Populated only by [`Error::aggregate`].
    aggregated: Vec<Error>,
}

impl Error {
    fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind: Box::new(kind),
            message: message.into(),
            source: None,
            aggregated: Vec::new(),
        }
    }

    /// Attaches the underlying cause, mirroring the upstream `{ cause }` option.
    #[must_use]
    pub fn with_source(mut self, source: impl StdError + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    #[must_use]
    pub fn puncode_security(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::PuncodeSecurity, message)
    }

    #[must_use]
    pub fn configuration(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Configuration, message)
    }

    #[must_use]
    pub fn authentication_required(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::AuthenticationRequired, message)
    }

    #[must_use]
    pub fn plugin_bootstrap(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::PluginBootstrap, message)
    }

    #[must_use]
    pub fn plugin_python_unavailable(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::PluginPythonUnavailable, message)
    }

    #[must_use]
    pub fn invalid_target(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidTarget, message)
    }

    #[must_use]
    pub fn output_directory(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::OutputDirectory, message)
    }

    #[must_use]
    pub fn incomplete_scan(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::IncompleteScan, message)
    }

    #[must_use]
    pub fn contract_validation(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::ContractValidation, message)
    }

    /// A scan output path that landed inside the protected scan root.
    #[must_use]
    pub fn output_inside_protected_root(
        output_directory: impl Into<PathBuf>,
        protected_root: impl Into<PathBuf>,
        path_kind: ProtectedScanPathKind,
    ) -> Self {
        let output_directory = output_directory.into();
        let message = format!(
            "Scan {path_kind} directory must be outside the protected scan root: {}",
            output_directory.display()
        );
        Self::new(
            ErrorKind::OutputInsideProtectedRoot {
                output_directory,
                protected_root: protected_root.into(),
                path_kind,
            },
            message,
        )
    }

    #[must_use]
    pub fn scan_interrupted(message: impl Into<String>, scan_dir: impl Into<PathBuf>) -> Self {
        Self::new(
            ErrorKind::ScanInterrupted {
                scan_dir: scan_dir.into(),
            },
            message,
        )
    }

    /// A scan stopped because its estimated cost passed the configured ceiling.
    #[must_use]
    pub fn scan_cost_limit_exceeded(
        max_cost_usd: f64,
        cost: ScanCost,
        scan_dir: impl Into<PathBuf>,
    ) -> Self {
        let scan_dir = scan_dir.into();
        let message = format!(
            "Scan stopped: estimated cost {} exceeded the {} limit; partial output remains at {}.",
            format_usd(cost.estimated_usd),
            format_usd(max_cost_usd),
            scan_dir.display()
        );
        Self::new(
            ErrorKind::ScanCostLimitExceeded {
                max_cost_usd,
                cost,
                scan_dir,
            },
            message,
        )
    }

    /// Several failures that happened together, under one message.
    ///
    /// Ported from upstream's `AggregateError`, raised when preparing a runtime
    /// fails *and* cleaning it up afterwards also fails. Both are kept: the
    /// cleanup failure explains a directory left behind, and losing either one
    /// would leave the other unexplained. The first is also exposed as the
    /// source, matching upstream's `cause`.
    pub fn aggregate(errors: impl IntoIterator<Item = Self>, message: impl Into<String>) -> Self {
        let errors: Vec<Self> = errors.into_iter().collect();
        let mut aggregate = Self::new(ErrorKind::Aggregate, message);
        if let Some(first) = errors.first() {
            aggregate.source = Some(Box::new(Self::new(
                *first.kind.clone(),
                first.message.clone(),
            )));
        }
        aggregate.aggregated = errors;
        aggregate
    }

    /// Attaches failures that happened alongside this one.
    ///
    /// Unlike [`Error::aggregate`], the primary failure keeps its own message
    /// and category, so callers that branch on it are unaffected; the rest stay
    /// reachable through [`Error::errors`] instead of being discarded.
    #[must_use]
    pub fn with_aggregated(mut self, errors: impl IntoIterator<Item = Self>) -> Self {
        self.aggregated.extend(errors);
        self
    }

    /// The individual failures gathered by [`Error::aggregate`], or attached by
    /// [`Error::with_aggregated`].
    ///
    /// Empty for every other error, so callers can ask unconditionally.
    #[must_use]
    pub fn errors(&self) -> &[Self] {
        &self.aggregated
    }

    #[must_use]
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// The name of the corresponding upstream error class.
    #[must_use]
    pub fn class_name(&self) -> &'static str {
        match *self.kind {
            ErrorKind::PuncodeSecurity => "PuncodeSecurityError",
            ErrorKind::Configuration => "ConfigurationError",
            ErrorKind::AuthenticationRequired => "AuthenticationRequiredError",
            ErrorKind::PluginBootstrap => "PluginBootstrapError",
            ErrorKind::PluginPythonUnavailable => "PluginPythonUnavailableError",
            ErrorKind::InvalidTarget => "InvalidTargetError",
            ErrorKind::OutputDirectory => "OutputDirectoryError",
            ErrorKind::OutputInsideProtectedRoot { .. } => "OutputInsideProtectedRootError",
            ErrorKind::IncompleteScan => "IncompleteScanError",
            ErrorKind::ContractValidation => "ContractValidationError",
            ErrorKind::ScanInterrupted { .. } => "ScanInterruptedError",
            ErrorKind::ScanCostLimitExceeded { .. } => "ScanCostLimitExceededError",
            ErrorKind::Aggregate => "AggregateError",
        }
    }

    /// True for `PluginBootstrapError` and its `PluginPythonUnavailableError`
    /// subclass.
    #[must_use]
    pub fn is_plugin_bootstrap(&self) -> bool {
        matches!(
            *self.kind,
            ErrorKind::PluginBootstrap | ErrorKind::PluginPythonUnavailable
        )
    }

    /// True for `OutputDirectoryError` and its
    /// `OutputInsideProtectedRootError` subclass.
    #[must_use]
    pub fn is_output_directory(&self) -> bool {
        matches!(
            *self.kind,
            ErrorKind::OutputDirectory | ErrorKind::OutputInsideProtectedRoot { .. }
        )
    }

    #[must_use]
    pub fn is_output_inside_protected_root(&self) -> bool {
        matches!(*self.kind, ErrorKind::OutputInsideProtectedRoot { .. })
    }

    /// True for `ScanInterruptedError` and its `ScanCostLimitExceededError`
    /// subclass.
    #[must_use]
    pub fn is_scan_interrupted(&self) -> bool {
        matches!(
            *self.kind,
            ErrorKind::ScanInterrupted { .. } | ErrorKind::ScanCostLimitExceeded { .. }
        )
    }

    #[must_use]
    pub fn is_scan_cost_limit_exceeded(&self) -> bool {
        matches!(*self.kind, ErrorKind::ScanCostLimitExceeded { .. })
    }

    #[must_use]
    pub fn is_contract_validation(&self) -> bool {
        matches!(*self.kind, ErrorKind::ContractValidation)
    }

    /// The partial output directory left behind by an interrupted scan.
    #[must_use]
    pub fn scan_dir(&self) -> Option<&Path> {
        match &*self.kind {
            ErrorKind::ScanInterrupted { scan_dir }
            | ErrorKind::ScanCostLimitExceeded { scan_dir, .. } => Some(scan_dir),
            _ => None,
        }
    }

    #[must_use]
    pub fn max_cost_usd(&self) -> Option<f64> {
        match *self.kind {
            ErrorKind::ScanCostLimitExceeded { max_cost_usd, .. } => Some(max_cost_usd),
            _ => None,
        }
    }

    #[must_use]
    pub fn cost(&self) -> Option<&ScanCost> {
        match &*self.kind {
            ErrorKind::ScanCostLimitExceeded { cost, .. } => Some(cost),
            _ => None,
        }
    }

    #[must_use]
    pub fn output_directory_path(&self) -> Option<&Path> {
        match &*self.kind {
            ErrorKind::OutputInsideProtectedRoot {
                output_directory, ..
            } => Some(output_directory),
            _ => None,
        }
    }

    #[must_use]
    pub fn protected_root(&self) -> Option<&Path> {
        match &*self.kind {
            ErrorKind::OutputInsideProtectedRoot { protected_root, .. } => Some(protected_root),
            _ => None,
        }
    }

    #[must_use]
    pub fn path_kind(&self) -> Option<ProtectedScanPathKind> {
        match *self.kind {
            ErrorKind::OutputInsideProtectedRoot { path_kind, .. } => Some(path_kind),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_ref()
            .map(|source| source.as_ref() as &(dyn StdError + 'static))
    }
}

/// The result type used throughout this crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;
