//! Non-activating panels. macOS no longer lets a background accessory app activate itself,
//! so a normal window or alert would open without keyboard focus while another app stays active.
//! A non-activating panel receives keys anyway.

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, Sel};
use objc2::{MainThreadMarker, MainThreadOnly, define_class, msg_send, sel};
use objc2_app_kit::{
    NSApplication, NSBackingStoreType, NSButton, NSControlStateValueOn, NSEvent,
    NSEventModifierFlags, NSFloatingWindowLevel, NSImage, NSImageView, NSPanel, NSPopUpButton,
    NSResponder, NSSecureTextField, NSTextField, NSView, NSWindow, NSWindowStyleMask,
};
use objc2_foundation::{NSObject, NSPoint, NSRect, NSSize, NSString, ns_string};

const WIDTH: f64 = 420.0;
const MARGIN: f64 = 20.0;
const EYE: f64 = 24.0;
const CHOOSE: f64 = 84.0;
/// The app icon on each panel's left, as native alerts show it. A genuine prompt from the app is
/// then recognizable at a glance.
const ICON: f64 = 56.0;

define_class!(
    /// A panel that handles Cmd+V, C, X, A, and Z itself. A menu-bar app has no Edit menu,
    /// and an inactive app's menu gets no key equivalents, so paste would do nothing.
    #[unsafe(super(NSPanel, NSWindow, NSResponder, NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "Fido2kitPanel"]
    struct KeyPanel;

    impl KeyPanel {
        #[unsafe(method(performKeyEquivalent:))]
        fn perform_key_equivalent(&self, event: &NSEvent) -> bool {
            // A nil target sends the action along the responder chain to the focused field.
            let handled = edit_action(event).is_some_and(|action| {
                let app = NSApplication::sharedApplication(self.mtm());
                unsafe { app.sendAction_to_from(action, None, None) }
            });
            handled || unsafe { msg_send![super(self), performKeyEquivalent: event] }
        }
    }
);

fn edit_action(event: &NSEvent) -> Option<Sel> {
    if !event
        .modifierFlags()
        .contains(NSEventModifierFlags::Command)
    {
        return None;
    }
    match event.charactersIgnoringModifiers()?.to_string().as_str() {
        "v" => Some(sel!(paste:)),
        "c" => Some(sel!(copy:)),
        "x" => Some(sel!(cut:)),
        "a" => Some(sel!(selectAll:)),
        "z" => Some(sel!(undo:)),
        _ => None,
    }
}

pub struct Field<'a> {
    pub label: &'a str,
    pub kind: Kind<'a>,
}

pub enum Kind<'a> {
    Text {
        value: &'a str,
        secure: bool,
        accessory: Option<Accessory>,
    },
    /// A pop-up menu. Its value is the selected option.
    Choice {
        options: Vec<String>,
        selected: usize,
    },
    /// A checkbox titled `title`. Its value is `title` when checked, and empty otherwise.
    Check { title: &'a str },
}

/// A button to the right of a text field. It sends its action with the field's index as its tag.
pub enum Accessory {
    /// For secure fields: an eye button that shows or hides the text.
    Reveal(Sel),
    /// A "Choose…" button, for a field that holds a path.
    Choose(Sel),
}

impl<'a> Field<'a> {
    pub fn plain(label: &'a str, value: &'a str) -> Self {
        let kind = Kind::Text {
            value,
            secure: false,
            accessory: None,
        };
        Self { label, kind }
    }

    /// A path field with a "Choose…" button.
    pub fn path(label: &'a str, value: &'a str, action: Sel) -> Self {
        let kind = Kind::Text {
            value,
            secure: false,
            accessory: Some(Accessory::Choose(action)),
        };
        Self { label, kind }
    }

    pub fn secret(label: &'a str) -> Self {
        let kind = Kind::Text {
            value: "",
            secure: true,
            accessory: None,
        };
        Self { label, kind }
    }

    /// A secret field with an eye button, for long passwords that are easy to mistype.
    pub fn revealable(label: &'a str, value: &'a str, action: Sel) -> Self {
        let kind = Kind::Text {
            value,
            secure: true,
            accessory: Some(Accessory::Reveal(action)),
        };
        Self { label, kind }
    }

    pub fn choice(label: &'a str, options: Vec<String>, selected: usize) -> Self {
        Self {
            label,
            kind: Kind::Choice { options, selected },
        }
    }

    pub fn check(label: &'a str, title: &'a str) -> Self {
        Self {
            label,
            kind: Kind::Check { title },
        }
    }
}

pub struct Button<'a> {
    pub title: &'a str,
    pub action: Sel,
    pub key: Key,
}

pub enum Key {
    Return,
    Escape,
}

enum Control {
    Text {
        field: Retained<NSTextField>,
        /// For revealable fields: a plain field at the same spot, shown while the text is visible.
        plain: Option<Retained<NSTextField>>,
        eye: Option<Retained<NSButton>>,
    },
    Choice(Retained<NSPopUpButton>),
    Check(Retained<NSButton>),
}

pub struct Form {
    pub panel: Retained<NSPanel>,
    controls: Vec<Control>,
}

impl Form {
    /// Reads every field in order, then clears the text fields, so typed secrets do not linger.
    /// A choice field yields its selected option, and a checked box its title.
    pub fn take_values(&self) -> Vec<zeroize::Zeroizing<String>> {
        self.controls
            .iter()
            .map(|control| match control {
                Control::Text { field, plain, .. } => {
                    let visible = plain.as_ref().filter(|p| !p.isHidden()).unwrap_or(field);
                    let value = zeroize::Zeroizing::new(visible.stringValue().to_string());
                    field.setStringValue(ns_string!(""));
                    if let Some(plain) = plain {
                        plain.setStringValue(ns_string!(""));
                    }
                    value
                }
                Control::Choice(popup) => zeroize::Zeroizing::new(
                    popup
                        .titleOfSelectedItem()
                        .map(|t| t.to_string())
                        .unwrap_or_default(),
                ),
                Control::Check(button) => {
                    zeroize::Zeroizing::new(if button.state() == NSControlStateValueOn {
                        button.title().to_string()
                    } else {
                        String::new()
                    })
                }
            })
            .collect()
    }

    /// Shows or hides the text of revealable field `index`, moving its text across.
    pub fn toggle_reveal(&self, index: usize) {
        let Some(Control::Text {
            field: secure,
            plain: Some(plain),
            eye: Some(eye),
        }) = self.controls.get(index)
        else {
            return;
        };
        let showing = !plain.isHidden();
        let (from, to) = if showing {
            (plain, secure)
        } else {
            (secure, plain)
        };
        to.setStringValue(&from.stringValue());
        from.setStringValue(ns_string!(""));
        from.setHidden(true);
        to.setHidden(false);
        self.panel.makeFirstResponder(Some(to));
        eye.setImage(eye_image(!showing).as_deref());
    }

    /// Replaces the text of text field `index`.
    pub fn set_text(&self, index: usize, value: &str) {
        if let Some(Control::Text { field, .. }) = self.controls.get(index) {
            field.setStringValue(&NSString::from_str(value));
        }
    }

    pub fn close(&self) {
        self.panel.orderOut(None);
    }
}

/// Builds and shows a panel: `message` on top, one row per field, and `buttons` right-aligned
/// at the bottom. Buttons send their actions to `target`.
pub fn form(
    mtm: MainThreadMarker,
    target: &AnyObject,
    title: &str,
    message: &str,
    fields: &[Field],
    buttons: &[Button],
) -> Form {
    let rect = |x, y, w, h| NSRect::new(NSPoint::new(x, y), NSSize::new(w, h));
    let text_left = MARGIN + ICON + 14.0;
    let text = NSTextField::wrappingLabelWithString(&NSString::from_str(message), mtm);
    text.setPreferredMaxLayoutWidth(WIDTH - text_left - MARGIN);
    let text_height = text.fittingSize().height;
    let head_height = text_height.max(ICON);
    let buttons_height = if buttons.is_empty() { 0.0 } else { 44.0 };
    let height = MARGIN + head_height + 12.0 + fields.len() as f64 * 32.0 + buttons_height + 12.0;

    let mask = NSWindowStyleMask::Titled | NSWindowStyleMask::NonactivatingPanel;
    let panel: Retained<KeyPanel> = unsafe {
        msg_send![
            KeyPanel::alloc(mtm),
            initWithContentRect: rect(0.0, 0.0, WIDTH, height),
            styleMask: mask,
            backing: NSBackingStoreType::Buffered,
            defer: false,
        ]
    };
    let panel: Retained<NSPanel> = Retained::into_super(panel);
    unsafe { panel.setReleasedWhenClosed(false) };
    panel.setTitle(&NSString::from_str(title));
    panel.setLevel(NSFloatingWindowLevel);
    // Panels hide while their app is inactive, and a menu-bar app never becomes the active app.
    panel.setHidesOnDeactivate(false);
    panel.setBecomesKeyOnlyIfNeeded(false);
    panel.setAutorecalculatesKeyViewLoop(true);
    let content = panel.contentView().expect("panels have a content view");

    let head_top = height - MARGIN;
    if let Some(icon) = NSApplication::sharedApplication(mtm).applicationIconImage() {
        let view = NSImageView::imageViewWithImage(&icon, mtm);
        view.setFrame(rect(MARGIN, head_top - ICON, ICON, ICON));
        content.addSubview(&view);
    }
    text.setFrame(rect(
        text_left,
        head_top - text_height,
        WIDTH - text_left - MARGIN,
        text_height,
    ));
    content.addSubview(&text);
    let mut top = head_top - head_height - 12.0;

    let mut controls = Vec::new();
    let mut first_text = None;
    for (index, field) in fields.iter().enumerate() {
        top -= 24.0;
        let label = NSTextField::labelWithString(&NSString::from_str(field.label), mtm);
        label.setFrame(rect(MARGIN, top + 2.0, 110.0, 20.0));
        content.addSubview(&label);
        let control = match &field.kind {
            Kind::Text {
                value,
                secure,
                accessory,
            } => {
                let side_width = match accessory {
                    Some(Accessory::Reveal(_)) => EYE,
                    Some(Accessory::Choose(_)) => CHOOSE,
                    None => 0.0,
                };
                let side_space = if accessory.is_some() {
                    side_width + 4.0
                } else {
                    0.0
                };
                let frame = rect(
                    MARGIN + 116.0,
                    top,
                    WIDTH - 2.0 * MARGIN - 116.0 - side_space,
                    24.0,
                );
                let text_field: Retained<NSTextField> = if *secure {
                    Retained::into_super(NSSecureTextField::initWithFrame(
                        NSSecureTextField::alloc(mtm),
                        frame,
                    ))
                } else {
                    NSTextField::initWithFrame(NSTextField::alloc(mtm), frame)
                };
                text_field.setStringValue(&NSString::from_str(value));
                content.addSubview(&text_field);
                first_text.get_or_insert_with(|| text_field.clone());
                let side = |title: &NSString, action: Sel| {
                    let button = unsafe {
                        NSButton::buttonWithTitle_target_action(
                            title,
                            Some(target),
                            Some(action),
                            mtm,
                        )
                    };
                    button.setTag(index as isize);
                    button.setFrame(rect(WIDTH - MARGIN - side_width, top, side_width, 24.0));
                    content.addSubview(&button);
                    button
                };
                let (plain, eye) = match accessory {
                    Some(Accessory::Choose(action)) => {
                        side(ns_string!("Choose…"), *action);
                        (None, None)
                    }
                    Some(Accessory::Reveal(action)) => {
                        let plain = NSTextField::initWithFrame(NSTextField::alloc(mtm), frame);
                        plain.setHidden(true);
                        content.addSubview(&plain);
                        let eye = side(ns_string!(""), *action);
                        eye.setBordered(false);
                        eye.setImage(eye_image(false).as_deref());
                        (Some(plain), Some(eye))
                    }
                    None => (None, None),
                };
                Control::Text {
                    field: text_field,
                    plain,
                    eye,
                }
            }
            Kind::Choice { options, selected } => {
                let popup = NSPopUpButton::initWithFrame_pullsDown(
                    NSPopUpButton::alloc(mtm),
                    rect(
                        MARGIN + 112.0,
                        top - 1.0,
                        WIDTH - 2.0 * MARGIN - 112.0,
                        26.0,
                    ),
                    false,
                );
                for option in options {
                    popup.addItemWithTitle(&NSString::from_str(option));
                }
                popup.selectItemAtIndex(*selected as isize);
                content.addSubview(&popup);
                Control::Choice(popup)
            }
            Kind::Check { title } => {
                let button = unsafe {
                    NSButton::checkboxWithTitle_target_action(
                        &NSString::from_str(title),
                        None,
                        None,
                        mtm,
                    )
                };
                button.setFrame(rect(
                    MARGIN + 116.0,
                    top,
                    WIDTH - 2.0 * MARGIN - 116.0,
                    24.0,
                ));
                content.addSubview(&button);
                Control::Check(button)
            }
        };
        controls.push(control);
        top -= 8.0;
    }

    let mut right = WIDTH - MARGIN + 6.0;
    for button in buttons {
        let control = unsafe {
            NSButton::buttonWithTitle_target_action(
                &NSString::from_str(button.title),
                Some(target),
                Some(button.action),
                mtm,
            )
        };
        let width = control.fittingSize().width.max(90.0);
        right -= width + 6.0;
        control.setFrame(rect(right, 12.0, width, 32.0));
        control.setKeyEquivalent(match button.key {
            Key::Return => ns_string!("\r"),
            Key::Escape => ns_string!("\u{1b}"),
        });
        content.addSubview(&*control as &NSView);
    }

    panel.center();
    panel.makeKeyAndOrderFront(None);
    if let Some(first) = &first_text {
        panel.makeFirstResponder(Some(first));
    }
    Form { panel, controls }
}

fn eye_image(showing: bool) -> Option<Retained<NSImage>> {
    let (name, description) = if showing {
        (ns_string!("eye.slash"), ns_string!("Hide password"))
    } else {
        (ns_string!("eye"), ns_string!("Show password"))
    };
    NSImage::imageWithSystemSymbolName_accessibilityDescription(name, Some(description))
}
