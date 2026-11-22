//! Egress and parent next-hop selection.

use std::fmt;
use std::sync::Arc;

use crate::config::{Config, EgressProfile};
use crate::parent::PreparedParent;
use crate::policy::{RequestMeta, selectors_match};

/// Routing failure classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoutingError {
    /// The configured egress reference is not valid.
    RouteInvalid,
    /// The configured parent reference is not valid.
    ParentInvalid,
}

impl fmt::Display for RoutingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RouteInvalid => "egress route is invalid",
            Self::ParentInvalid => "parent route is invalid",
        })
    }
}

impl std::error::Error for RoutingError {}

/// One first-match route: one egress and either direct or one parent.
pub struct RouteSelection<'a> {
    egress: &'a EgressProfile,
    parent: Option<&'a Arc<PreparedParent>>,
    routing_rule_id: Option<&'a str>,
}

impl<'a> RouteSelection<'a> {
    /// Selected egress profile.
    pub fn egress(&self) -> &'a EgressProfile {
        self.egress
    }

    /// Selected parent, or `None` for direct.
    pub fn parent(&self) -> Option<&'a Arc<PreparedParent>> {
        self.parent
    }

    /// Matched routing rule, or `None` when the defaults were used.
    pub fn routing_rule_id(&self) -> Option<&'a str> {
        self.routing_rule_id
    }
}

/// Selects exactly one egress and next hop for an already allowed request.
pub fn select_route<'a>(
    config: &'a Config,
    meta: &RequestMeta<'_>,
) -> Result<RouteSelection<'a>, RoutingError> {
    let routing = config.routing();
    let rule = routing
        .rules()
        .iter()
        .find(|rule| selectors_match(rule.selectors(), meta));

    let egress_id = rule.map_or_else(|| routing.default_egress(), |rule| rule.egress_id());
    let next_hop = match rule {
        Some(rule) => match rule.next_hop() {
            Some(value) => Some(value),
            None => routing.default_parent(),
        },
        None => routing.default_parent(),
    };
    let parent = match next_hop {
        Some("direct") | None => None,
        Some(id) => Some(config.parent(id).ok_or(RoutingError::ParentInvalid)?),
    };
    let egress = config
        .egress()
        .iter()
        .find(|profile| profile.id() == egress_id)
        .ok_or(RoutingError::RouteInvalid)?;

    Ok(RouteSelection {
        egress,
        parent,
        routing_rule_id: rule.map(|rule| rule.id()),
    })
}
