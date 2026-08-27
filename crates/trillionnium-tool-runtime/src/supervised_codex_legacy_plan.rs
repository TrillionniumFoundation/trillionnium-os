//! Historical plan/effect vocabulary used only by explicit conformance builds.

pub(super) const BROWSER_ACTION: &str = "browser_open_bounded";
pub(super) const NOTIFICATION_ACTION: &str = "notification_post_bounded";
pub(super) const BROWSER_TOOL: &str = "android.browser.open_bounded";
pub(super) const NOTIFICATION_TOOL: &str = "android.notification.post_bounded";
pub(super) const BROWSER_UNDO: &str = "no_undo_external_browser_launch";
pub(super) const NOTIFICATION_UNDO: &str = "cancel_exact_owned_notification";
pub(super) const ALLOWED_ACTIONS: &[&str] = &[BROWSER_ACTION, NOTIFICATION_ACTION];
