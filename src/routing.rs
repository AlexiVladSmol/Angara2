//! Egress profile selection.

use std::fmt;

use crate::config::{EgressProfile, RoutingConfig};
use crate::policy::{RequestMeta, selectors_match};

/// Routing failure classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutingError {
    /// The configured egress reference is not valid.
    RouteInvalid,
}

impl fmt::Display for RoutingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("egress route is invalid")
    }
}

impl std::error::Error for RoutingError {}

/// Selects exactly one egress profile for an already allowed request.
pub fn select_egress<'a>(
    routing: &'a RoutingConfig,
    egresses: &'a [EgressProfile],
    meta: &RequestMeta<'_>,
) -> Result<&'a EgressProfile, RoutingError> {
    let egress_id = routing
        .rules()
        .iter()
        .find(|rule| selectors_match(rule.selectors(), meta))
        .map_or_else(|| routing.default_egress(), |rule| rule.egress_id());

    egresses
        .iter()
        .find(|profile| profile.id() == egress_id)
        .ok_or(RoutingError::RouteInvalid)
}
