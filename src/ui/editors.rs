use std::{cell::Cell, rc::Rc, sync::Arc, time::Duration};

use super::LabeledEntry;
use adw::prelude::*;
use anyhow::{Context, Result, ensure};
use gtk::glib;
use serde_json::{Value, json};
use sourceview::prelude::*;

use crate::{
    engine::Service,
    model::{self, RuleSet, Subscription},
};

type Saved = Rc<dyn Fn()>;
type SaveText = (Arc<dyn Fn(String) -> Result<()> + Send + Sync>, Saved);

struct EditorWindow {
    window: adw::Window,
    body: gtk::Box,
    save: gtk::Button,
    cancel: gtk::Button,
    error: gtk::Label,
    saving: Rc<Cell<bool>>,
}

impl EditorWindow {
    fn new(parent: &impl IsA<gtk::Window>, title: &str, subtitle: &str) -> Self {
        let window = adw::Window::builder()
            .title(title)
            .transient_for(parent)
            .modal(true)
            .default_width(880)
            .default_height(740)
            .build();
        if let Some(app) = parent.application() {
            window.set_application(Some(&app));
        }
        let saving = Rc::new(Cell::new(false));
        let guard = saving.clone();
        window.connect_close_request(move |_| {
            if guard.get() {
                glib::Propagation::Stop
            } else {
                glib::Propagation::Proceed
            }
        });
        let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
        root.add_css_class("editor-root");
        let header = adw::HeaderBar::new();
        header.set_show_end_title_buttons(false);
        header.set_show_start_title_buttons(false);
        header.set_title_widget(Some(&adw::WindowTitle::new(title, subtitle)));
        let cancel = gtk::Button::with_label("取消");
        cancel.add_css_class("flat");
        let weak = window.downgrade();
        cancel.connect_clicked(move |_| {
            if let Some(w) = weak.upgrade() {
                w.close();
            }
        });
        let save = gtk::Button::with_label("保存");
        save.add_css_class("suggested-action");
        save.add_css_class("primary-action");
        // Enter inside any entry finishes the dialog instead of silently doing
        // nothing; Ctrl+Enter in the source view still inserts a newline.
        window.set_default_widget(Some(&save));
        header.pack_start(&cancel);
        header.pack_end(&save);
        root.append(&header);
        let body = gtk::Box::new(gtk::Orientation::Vertical, 0);
        body.set_vexpand(true);
        root.append(&body);
        let error = gtk::Label::builder()
            .wrap(true)
            .xalign(0.0)
            .margin_start(24)
            .margin_end(24)
            .margin_top(8)
            .margin_bottom(16)
            .selectable(true)
            .visible(false)
            .build();
        error.add_css_class("error");
        root.append(&error);
        window.set_content(Some(&root));
        Self {
            window,
            body,
            save,
            cancel,
            error,
            saving,
        }
    }
}

fn explain(text: &str) -> gtk::Label {
    let label = gtk::Label::builder()
        .label(text)
        .xalign(0.0)
        .wrap(true)
        .build();
    label.add_css_class("dim-label");
    label
}
fn form_page() -> (gtk::ScrolledWindow, gtk::Box) {
    let form = gtk::Box::new(gtk::Orientation::Vertical, 24);
    form.set_margin_top(24);
    form.set_margin_bottom(32);
    form.set_margin_start(24);
    form.set_margin_end(24);
    let clamp = adw::Clamp::builder()
        .maximum_size(740)
        .tightening_threshold(600)
        .child(&form)
        .build();
    let scroll = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .child(&clamp)
        .build();
    (scroll, form)
}
fn group(title: &str, description: &str) -> adw::PreferencesGroup {
    adw::PreferencesGroup::builder()
        .title(title)
        .description(description)
        .build()
}
fn switch(title: &str, subtitle: &str, active: bool) -> adw::SwitchRow {
    adw::SwitchRow::builder()
        .title(title)
        .subtitle(subtitle)
        .active(active)
        .build()
}
fn show_error(label: &gtk::Label, error: impl std::fmt::Display) {
    label.set_text(&format!("{error:#}"));
    label.set_visible(true);
}
fn tabs(body: &gtk::Box) -> gtk::Stack {
    let stack = gtk::Stack::builder()
        .vexpand(true)
        .hexpand(true)
        .hhomogeneous(false)
        .vhomogeneous(false)
        .transition_type(gtk::StackTransitionType::Crossfade)
        .build();
    let switcher = gtk::StackSwitcher::builder()
        .stack(&stack)
        .halign(gtk::Align::Center)
        .margin_top(12)
        .margin_bottom(12)
        .build();
    switcher.add_css_class("editor-tabs");
    body.append(&switcher);
    body.append(&stack);
    stack
}

#[derive(Clone)]
struct SourceEditor {
    root: gtk::Box,
    buffer: sourceview::Buffer,
}
impl SourceEditor {
    fn new(text: &str, language: &str, editable: bool, hint: &str) -> Self {
        let root = gtk::Box::new(gtk::Orientation::Vertical, 12);
        root.set_margin_top(16);
        root.set_margin_bottom(24);
        root.set_margin_start(24);
        root.set_margin_end(24);
        root.set_vexpand(true);
        if !hint.is_empty() {
            root.append(&explain(hint));
        }
        let buffer = sourceview::Buffer::new(None);
        buffer.set_text(text);
        let language = sourceview::LanguageManager::default().language(language);
        buffer.set_language(language.as_ref());
        let manager = sourceview::StyleSchemeManager::default();
        let dark = adw::StyleManager::default().is_dark();
        let scheme = manager
            .scheme(if dark { "Adwaita-dark" } else { "Adwaita" })
            .or_else(|| manager.scheme(if dark { "oblivion" } else { "classic" }));
        buffer.set_style_scheme(scheme.as_ref());
        let view = sourceview::View::with_buffer(&buffer);
        view.set_monospace(true);
        view.set_editable(editable);
        view.set_show_line_numbers(true);
        view.set_auto_indent(true);
        view.set_tab_width(2);
        view.set_insert_spaces_instead_of_tabs(true);
        view.set_highlight_current_line(editable);
        view.set_top_margin(14);
        view.set_bottom_margin(14);
        view.set_left_margin(12);
        view.set_right_margin(12);
        let scroll = gtk::ScrolledWindow::builder()
            .vexpand(true)
            .hexpand(true)
            .child(&view)
            .build();
        scroll.add_css_class("card");
        root.append(&scroll);
        Self { root, buffer }
    }
    fn text(&self) -> String {
        self.buffer
            .text(&self.buffer.start_iter(), &self.buffer.end_iter(), false)
            .into()
    }
}

/// Common fields update only the fields the user actually changed. The full JSON
/// remains authoritative for every other field, including unknown core options.
pub fn subscription(
    parent: &adw::ApplicationWindow,
    service: Arc<Service>,
    item: Subscription,
    on_saved: Saved,
) {
    let editor = EditorWindow::new(parent, "编辑订阅", "");
    let (scroll, form) = form_page();
    let source_group = group("订阅来源", "");
    let name = LabeledEntry::new("名称", &item.name);
    let source = LabeledEntry::new("订阅地址或文件路径", &item.source);
    source.entry.set_tooltip_text(Some("留空可手动添加节点"));
    let choose = gtk::Button::from_icon_name("document-open-symbolic");
    choose.set_tooltip_text(Some("选择本地订阅文件"));
    choose.add_css_class("flat");
    source.with_suffix(&choose);
    let name_row = name.root.clone();
    let source_row = source.root.clone();
    let source_for_file = source.clone();
    let weak = editor.window.downgrade();
    choose.connect_clicked(move |_| {
        if let Some(parent) = weak.upgrade() {
            let source = source_for_file.clone();
            glib::MainContext::default().spawn_local(async move {
                if let Ok(file) = gtk::FileDialog::new().open_future(Some(&parent)).await
                    && let Some(path) = file.path()
                {
                    source.set_text(&path.to_string_lossy());
                }
            });
        }
    });
    source_group.add(&name_row);
    source_group.add(&source_row);
    form.append(&source_group);
    let updates = group("更新", "");
    let auto_update = switch("自动更新", "", item.auto_update);
    let interval = adw::SpinRow::with_range(1.0, 168.0, 1.0);
    interval.set_title("更新间隔（小时）");
    interval.set_value(item.update_interval_hours as f64);
    interval.set_sensitive(item.auto_update);
    let interval_toggle = interval.clone();
    auto_update.connect_active_notify(move |row| interval_toggle.set_sensitive(row.is_active()));
    updates.add(&auto_update);
    updates.add(&interval);
    form.append(&updates);
    let edit_nodes = gtk::Button::with_label("编辑节点数据");
    edit_nodes.set_halign(gtk::Align::Start);
    let weak = editor.window.downgrade();
    let nodes_service = service.clone();
    let nodes_id = item.id.clone();
    let nodes_saved = on_saved.clone();
    edit_nodes.connect_clicked(move |_| {
        if let Some(parent) = weak.upgrade()
            && let Some(subscription) = nodes_service
                .snapshot()
                .subscriptions
                .into_iter()
                .find(|s| s.id == nodes_id)
        {
            nodes(
                &parent,
                nodes_service.clone(),
                subscription,
                nodes_saved.clone(),
            );
        }
    });
    form.append(&edit_nodes);
    editor.body.append(&scroll);
    let weak = editor.window.downgrade();
    let error = editor.error.clone();
    editor.save.connect_clicked(move |_| {
        let result = (|| -> Result<()> {
            ensure!(!name.text().trim().is_empty(), "请填写订阅名称");
            service.update(|state| {
                // Keep freshly downloaded nodes and quota information if a
                // background update completed while the form was open.
                let mut next = state
                    .subscriptions
                    .iter()
                    .find(|s| s.id == item.id)
                    .cloned()
                    .unwrap_or_else(|| item.clone());
                next.name = name.text().trim().into();
                let input = source.text();
                let input = input.trim();
                let updated_source = if input.contains("://") {
                    let parsed = aerobox_for_linux::subscription::import_input(input)?;
                    ensure!(!parsed.source.is_empty(), "这里需要订阅地址");
                    parsed.source
                } else {
                    input.to_owned()
                };
                if next.source != updated_source {
                    next.updated = 0;
                }
                next.source = updated_source;
                next.auto_update = auto_update.is_active() && !next.source.is_empty();
                next.update_interval_hours = interval.value() as u32;
                if let Some(old) = state.subscriptions.iter_mut().find(|s| s.id == next.id) {
                    *old = next;
                } else {
                    state.subscriptions.push(next);
                }
                Ok(())
            })
        })();
        match result {
            Ok(()) => {
                on_saved();
                if let Some(w) = weak.upgrade() {
                    w.close();
                }
            }
            Err(err) => show_error(&error, err),
        }
    });
    editor.window.present();
}

fn common_rule(kind: &str, text: &str) -> Result<Value> {
    let value = text.trim();
    ensure!(!value.is_empty(), "请填写匹配值");
    let field = match kind {
        "port" => {
            let port: u16 = value.parse().context("端口须为 1 到 65535")?;
            ensure!(port > 0, "端口须为 1 到 65535");
            json!([port])
        }
        "ip_cidr" => {
            let (address, prefix) = value
                .split_once('/')
                .context("请填写 IP/前缀长度，如 192.168.1.0/24")?;
            let address: std::net::IpAddr = address.parse().context("IP 地址无效")?;
            let prefix: u8 = prefix.parse().context("前缀长度无效")?;
            ensure!(
                prefix <= if address.is_ipv4() { 32 } else { 128 },
                "前缀长度超出范围"
            );
            json!([value])
        }
        "domain" | "domain_suffix" => {
            ensure!(
                !value.contains("://")
                    && !value.contains('/')
                    && !value.chars().any(char::is_whitespace),
                "请填写域名，不含协议或路径"
            );
            json!([value.trim_start_matches('.')])
        }
        "domain_keyword" | "process_name" => json!([value]),
        _ => anyhow::bail!("不支持的匹配类型"),
    };
    Ok(json!({kind: field}))
}

pub fn ruleset(
    parent: &adw::ApplicationWindow,
    service: Arc<Service>,
    item: RuleSet,
    on_saved: Saved,
) {
    let editor = EditorWindow::new(parent, "编辑规则集", "");
    let stack = tabs(&editor.body);
    stack.set_widget_name("ruleset-tabs");
    let (scroll, form) = form_page();
    let basic = group("规则集", "");
    let name = LabeledEntry::new("名称", &item.name);
    let source = LabeledEntry::new("在线地址或本地文件", &item.source);
    let name_row = name.root.clone();
    let source_row = source.root.clone();
    let interval = adw::SpinRow::with_range(1.0, 168.0, 1.0);
    interval.set_title("自动更新间隔（小时）");
    interval.set_value(item.update_interval_hours as f64);
    interval.set_visible(item.is_remote());
    let format_model = gtk::StringList::new(&["JSON 源文件", "SRS 二进制文件"]);
    let format = adw::ComboRow::builder()
        .title("文件格式")
        .model(&format_model)
        .selected(u32::from(item.binary))
        .build();
    basic.add(&name_row);
    basic.add(&source_row);
    basic.add(&format);
    basic.add(&interval);
    let actions = ["direct", "proxy", "reject"];
    let action = adw::ComboRow::builder()
        .title("匹配后")
        .model(&gtk::StringList::new(&["直连", "代理", "拦截"]))
        .selected(
            actions
                .iter()
                .position(|value| *value == item.action)
                .unwrap_or(0) as u32,
        )
        .build();
    let enabled = switch("启用", "", item.enabled);
    basic.add(&action);
    basic.add(&enabled);
    form.append(&basic);
    stack.add_titled(&scroll, Some("general"), "基本信息");
    let content = SourceEditor::new(&model::pretty(&item.content), "json", true, "");
    let rules = gtk::Box::new(gtk::Orientation::Vertical, 12);
    let quick = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    quick.set_margin_start(24);
    quick.set_margin_end(24);
    let kinds = [
        "domain",
        "domain_suffix",
        "domain_keyword",
        "ip_cidr",
        "process_name",
        "port",
    ];
    let kind = gtk::DropDown::from_strings(&[
        "域名",
        "域名后缀",
        "域名关键字",
        "IP 网段",
        "进程名",
        "端口",
    ]);
    let value = gtk::Entry::builder()
        .placeholder_text("匹配值")
        .hexpand(true)
        .build();
    let add_rule = gtk::Button::with_label("添加规则");
    quick.append(&kind);
    quick.append(&value);
    quick.append(&add_rule);
    rules.append(&quick);
    rules.append(&content.root);
    let content_page = stack.add_titled(&rules, Some("content"), "规则内容");
    content_page.set_visible(!item.is_remote());
    let switcher = stack.prev_sibling().expect("editor tabs");
    switcher.set_visible(!item.is_remote());
    let switcher = switcher.downgrade();
    let remote_interval = interval.clone();
    source.entry.connect_changed(move |source| {
        let online = model::is_online_source(source.text().trim());
        remote_interval.set_visible(online);
        content_page.set_visible(!online);
        if let Some(switcher) = switcher.upgrade() {
            switcher.set_visible(!online);
        }
    });
    let content_for_format = rules.clone();
    content_for_format.set_sensitive(!item.binary);
    format
        .connect_selected_notify(move |row| content_for_format.set_sensitive(row.selected() == 0));
    let buffer = content.buffer.clone();
    let quick_error = editor.error.clone();
    add_rule.connect_clicked(move |_| {
        let result = (|| -> Result<()> {
            let mut current = parse_json_buffer(&buffer)?;
            validate_rules(&current)?;
            let rule = common_rule(kinds[kind.selected() as usize], value.text().as_str())?;
            current["rules"]
                .as_array_mut()
                .context("规则列表无效")?
                .push(rule);
            buffer.set_text(&model::pretty(&current));
            value.set_text("");
            Ok(())
        })();
        match result {
            Ok(()) => quick_error.set_visible(false),
            Err(e) => show_error(&quick_error, e),
        }
    });
    let weak = editor.window.downgrade();
    let error = editor.error.clone();
    let cancel = editor.cancel.downgrade();
    let body = editor.body.downgrade();
    let saving = editor.saving.clone();
    editor.save.connect_clicked(move |button| {
        let result = (|| -> Result<RuleSet> {
            ensure!(!name.text().trim().is_empty(), "请填写规则集名称");
            let binary = format.selected() == 1;
            let source_text = source.text().trim().to_owned();
            let online = model::is_online_source(&source_text);
            let value = if !binary && !online {
                let value = parse_json_buffer(&content.buffer)?;
                validate_rules(&value)?;
                Some(value)
            } else {
                None
            };
            let mut next = service
                .snapshot()
                .rulesets
                .into_iter()
                .find(|r| r.id == item.id)
                .unwrap_or_else(|| item.clone());
            next.name = name.text().trim().into();
            next.source = source_text;
            next.update_interval_hours = interval.value() as u32;
            next.binary = binary;
            next.action = actions[action.selected() as usize].into();
            next.enabled = enabled.is_active();
            // A completed background update stays intact when only metadata
            // was edited. Explicit content edits remain authoritative.
            if let Some(value) = value
                && (item.binary || value != item.content)
            {
                next.content = value;
            }
            Ok(next)
        })();
        match result {
            Ok(next) => {
                saving.set(true);
                error.set_visible(false);
                button.set_sensitive(false);
                let spinner = gtk::Spinner::new();
                spinner.start();
                let progress = gtk::Box::new(gtk::Orientation::Horizontal, 8);
                progress.append(&spinner);
                progress.append(&gtk::Label::new(Some("保存中…")));
                button.set_child(Some(&progress));
                if let Some(cancel) = cancel.upgrade() {
                    cancel.set_sensitive(false);
                }
                if let Some(body) = body.upgrade() {
                    body.set_sensitive(false);
                }
                let service = service.clone();
                let (tx, rx) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    let _ = tx.send(service.save_ruleset(next));
                });
                let weak = weak.clone();
                let error = error.clone();
                let button = button.downgrade();
                let cancel = cancel.clone();
                let body = body.clone();
                let saving = saving.clone();
                let on_saved = on_saved.clone();
                glib::timeout_add_local(Duration::from_millis(40), move || {
                    let result = match rx.try_recv() {
                        Ok(result) => result,
                        Err(std::sync::mpsc::TryRecvError::Empty) => {
                            return glib::ControlFlow::Continue;
                        }
                        Err(_) => Err(anyhow::anyhow!("保存任务意外结束")),
                    };
                    saving.set(false);
                    spinner.stop();
                    if let Some(button) = button.upgrade() {
                        button.set_label("保存");
                        button.set_sensitive(true);
                    }
                    if let Some(cancel) = cancel.upgrade() {
                        cancel.set_sensitive(true);
                    }
                    if let Some(body) = body.upgrade() {
                        body.set_sensitive(true);
                    }
                    match result {
                        Ok(()) => {
                            on_saved();
                            if let Some(window) = weak.upgrade() {
                                window.close();
                            }
                        }
                        Err(error_text) => show_error(&error, error_text),
                    }
                    glib::ControlFlow::Break
                });
            }
            Err(err) => show_error(&error, err),
        }
    });
    editor.window.present();
}

pub fn nodes(
    parent: &impl IsA<gtk::Window>,
    service: Arc<Service>,
    item: Subscription,
    on_saved: Saved,
) {
    code(
        parent,
        &format!("{} · 节点", item.name),
        &model::pretty(&item.nodes),
        "json",
        Some((
            Arc::new(move |text| {
                let nodes = aerobox_for_linux::subscription::parse(&text)?;
                service.save_subscription_nodes(&item, nodes)
            }),
            on_saved,
        )),
    );
}

pub fn code(
    parent: &impl IsA<gtk::Window>,
    title: &str,
    text: &str,
    language: &str,
    on_save: Option<SaveText>,
) {
    let editor = EditorWindow::new(
        parent,
        title,
        if on_save.is_some() {
            "编辑内容"
        } else {
            "只读预览"
        },
    );
    let source = SourceEditor::new(text, language, on_save.is_some(), "");
    let toolbar = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    toolbar.add_css_class("editor-toolbar");
    let copy = gtk::Button::with_label("复制");
    copy.add_css_class("compact-action");
    let buf = source.buffer.clone();
    copy.connect_clicked(move |button| {
        button.clipboard().set_text(&buffer_text(&buf));
    });
    toolbar.append(&copy);
    let export = gtk::Button::with_label("导出文件");
    export.add_css_class("compact-action");
    let buf = source.buffer.clone();
    let weak = editor.window.downgrade();
    let err = editor.error.clone();
    let extension = language.to_string();
    export.connect_clicked(move |_| {
        if let Some(parent) = weak.upgrade() {
            let text = buffer_text(&buf);
            let err = err.clone();
            let ext = extension.clone();
            glib::MainContext::default().spawn_local(async move {
                let chooser = gtk::FileDialog::builder()
                    .title("导出文件")
                    .initial_name(format!("AeroBox.{ext}"))
                    .build();
                if let Ok(file) = chooser.save_future(Some(&parent)).await
                    && let Some(path) = file.path()
                    && let Err(e) = model::atomic_write(&path, text.as_bytes(), 0o600)
                {
                    show_error(&err, e);
                }
            });
        }
    });
    toolbar.append(&export);
    if on_save.is_some() {
        let import = gtk::Button::with_label("打开文件");
        import.add_css_class("compact-action");
        let buf = source.buffer.clone();
        let weak = editor.window.downgrade();
        let err = editor.error.clone();
        import.connect_clicked(move |_| {
            if let Some(parent) = weak.upgrade() {
                let buf = buf.clone();
                let err = err.clone();
                glib::MainContext::default().spawn_local(async move {
                    if let Ok(file) = gtk::FileDialog::new().open_future(Some(&parent)).await {
                        match file.load_contents_future().await {
                            Ok((bytes, _)) => match String::from_utf8(bytes.to_vec()) {
                                Ok(text) => buf.set_text(&text),
                                Err(e) => show_error(&err, e),
                            },
                            Err(e) => show_error(&err, e),
                        }
                    }
                });
            }
        });
        toolbar.append(&import);
    }
    if ["json", "yaml"].contains(&language) && on_save.is_some() {
        let format = gtk::Button::with_label("格式化");
        format.add_css_class("compact-action");
        let buf = source.buffer.clone();
        let lang = language.to_string();
        let err = editor.error.clone();
        format.connect_clicked(move |_| {
            let result = (|| -> Result<String> {
                if lang == "json" {
                    Ok(model::pretty(&parse_json_buffer(&buf)?))
                } else {
                    let value: Value = serde_yaml_ng::from_str(&buffer_text(&buf))?;
                    Ok(serde_yaml_ng::to_string(&value)?)
                }
            })();
            match result {
                Ok(text) => {
                    buf.set_text(&text);
                    err.set_visible(false)
                }
                Err(e) => show_error(&err, e),
            }
        });
        toolbar.append(&format);
    }
    source.root.prepend(&toolbar);
    editor.body.append(&source.root);
    let weak = editor.window.downgrade();
    let err = editor.error.clone();
    if let Some((save, on_saved)) = on_save {
        let saving = editor.saving.clone();
        let cancel = editor.cancel.clone();
        let body = editor.body.clone();
        editor.save.connect_clicked(move |button| {
            if saving.replace(true) {
                return;
            }
            err.set_visible(false);
            let progress = gtk::Box::new(gtk::Orientation::Horizontal, 8);
            let spinner = gtk::Spinner::builder().spinning(true).build();
            progress.append(&spinner);
            progress.append(&gtk::Label::new(Some("保存中…")));
            button.set_child(Some(&progress));
            button.set_sensitive(false);
            cancel.set_sensitive(false);
            body.set_sensitive(false);
            let text = source.text();
            let work = save.clone();
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(work(text));
            });
            let weak = weak.clone();
            let err = err.clone();
            let saving = saving.clone();
            let cancel = cancel.clone();
            let body = body.clone();
            let button = button.clone();
            let on_saved = on_saved.clone();
            glib::timeout_add_local(Duration::from_millis(40), move || {
                let result = match rx.try_recv() {
                    Ok(result) => result,
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        return glib::ControlFlow::Continue;
                    }
                    Err(_) => Err(anyhow::anyhow!("保存任务意外结束")),
                };
                saving.set(false);
                spinner.stop();
                button.set_label("保存");
                button.set_sensitive(true);
                cancel.set_sensitive(true);
                body.set_sensitive(true);
                match result {
                    Ok(()) => {
                        on_saved();
                        if let Some(w) = weak.upgrade() {
                            w.close();
                        }
                    }
                    Err(error) => show_error(&err, error),
                }
                glib::ControlFlow::Break
            });
        });
    } else {
        editor.save.set_label("完成");
        editor.save.connect_clicked(move |_| {
            if let Some(w) = weak.upgrade() {
                w.close();
            }
        });
    }
    editor.window.present();
}

pub fn rule_content(
    parent: &adw::ApplicationWindow,
    service: Arc<Service>,
    item: RuleSet,
    on_saved: Saved,
) {
    if !item.binary {
        code(
            parent,
            &format!("{} · 规则", item.name),
            &model::pretty(&item.content),
            "json",
            Some((
                Arc::new(move |text| {
                    let value: Value = serde_json::from_str(&text)?;
                    validate_rules(&value)?;
                    service.save_rule_source(&item.id, &text)
                }),
                on_saved,
            )),
        );
        return;
    }
    let editor = EditorWindow::new(parent, &format!("{} · 规则", item.name), "SRS 编译与反编译");
    editor.save.set_sensitive(false);
    let loading = gtk::Spinner::builder()
        .spinning(true)
        .halign(gtk::Align::Center)
        .valign(gtk::Align::Center)
        .vexpand(true)
        .build();
    editor.body.append(&loading);
    let (send, recv) = std::sync::mpsc::channel();
    let work = service.clone();
    let id = item.id.clone();
    std::thread::spawn(move || {
        let _ = send.send(work.rule_source(&id));
    });
    let body = editor.body.clone();
    let error = editor.error.clone();
    let save = editor.save.clone();
    let cancel = editor.cancel.clone();
    let saving = editor.saving.clone();
    let weak = editor.window.downgrade();
    glib::timeout_add_local(Duration::from_millis(30), move || {
        if weak.upgrade().is_none() {
            return glib::ControlFlow::Break;
        }
        match recv.try_recv() {
            Ok(result) => {
                body.remove(&loading);
                match result {
                    Ok(text) => {
                        let source = SourceEditor::new(
                            &text,
                            "json",
                            true,
                            "保存时使用 sing-box 编译为 SRS；编译失败会保留输入。",
                        );
                        body.append(&source.root);
                        save.set_sensitive(true);
                        let service = service.clone();
                        let id = item.id.clone();
                        let on_saved = on_saved.clone();
                        let error = error.clone();
                        let weak = weak.clone();
                        let cancel = cancel.clone();
                        let saving = saving.clone();
                        save.connect_clicked(move |button| {
                            let text = source.text();
                            if let Err(e) = serde_json::from_str::<Value>(&text)
                                .context("JSON 格式错误")
                                .and_then(|v| validate_rules(&v))
                            {
                                show_error(&error, e);
                                return;
                            }
                            button.set_sensitive(false);
                            button.set_label("保存中…");
                            cancel.set_sensitive(false);
                            source.root.set_sensitive(false);
                            saving.set(true);
                            error.set_visible(false);
                            let work = service.clone();
                            let id = id.clone();
                            let (send, recv) = std::sync::mpsc::channel();
                            std::thread::spawn(move || {
                                let _ = send.send(work.save_rule_source(&id, &text));
                            });
                            let weak = weak.clone();
                            let error = error.clone();
                            let button = button.clone();
                            let on_saved = on_saved.clone();
                            let cancel = cancel.clone();
                            let saving = saving.clone();
                            let source_root = source.root.clone();
                            glib::timeout_add_local(Duration::from_millis(30), move || match recv
                                .try_recv()
                            {
                                Ok(result) => {
                                    saving.set(false);
                                    button.set_sensitive(true);
                                    button.set_label("保存");
                                    cancel.set_sensitive(true);
                                    source_root.set_sensitive(true);
                                    match result {
                                        Ok(()) => {
                                            on_saved();
                                            if let Some(w) = weak.upgrade() {
                                                w.close()
                                            }
                                        }
                                        Err(e) => show_error(&error, e),
                                    };
                                    glib::ControlFlow::Break
                                }
                                Err(std::sync::mpsc::TryRecvError::Empty) => {
                                    glib::ControlFlow::Continue
                                }
                                Err(_) => {
                                    saving.set(false);
                                    button.set_sensitive(true);
                                    button.set_label("保存");
                                    cancel.set_sensitive(true);
                                    source_root.set_sensitive(true);
                                    show_error(&error, "编译任务意外结束");
                                    glib::ControlFlow::Break
                                }
                            });
                        });
                    }
                    Err(e) => show_error(&error, e),
                };
                glib::ControlFlow::Break
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
            Err(_) => {
                show_error(&error, "读取任务意外结束");
                glib::ControlFlow::Break
            }
        }
    });
    editor.window.present();
}

fn buffer_text(buffer: &sourceview::Buffer) -> String {
    buffer
        .text(&buffer.start_iter(), &buffer.end_iter(), false)
        .into()
}
fn parse_json_buffer(buffer: &sourceview::Buffer) -> Result<Value> {
    serde_json::from_str(&buffer_text(buffer)).context("JSON 格式错误")
}
fn validate_rules(value: &Value) -> Result<()> {
    ensure!(
        value.is_object() && value["rules"].is_array(),
        "规则集需要包含 rules 数组"
    );
    ensure!(
        value["version"].as_u64().is_some(),
        "规则集需要填写 version"
    );
    Ok(())
}

pub(super) fn smoke_ruleset(
    parent: &adw::ApplicationWindow,
    service: Arc<Service>,
    verify: bool,
) -> Result<()> {
    if verify {
        let rule = service
            .snapshot()
            .rulesets
            .into_iter()
            .find(|r| r.id == model::BUILTIN_DOMESTIC_ID)
            .context("缺少规则")?;
        ensure!(
            rule.is_remote()
                && rule.update_interval_hours == 12
                && rule.action == "direct"
                && rule.enabled,
            "规则保存没有生效"
        );
        return Ok(());
    }
    fn descendants(root: &impl IsA<gtk::Widget>) -> Vec<gtk::Widget> {
        let mut result = Vec::new();
        let mut child = root.first_child();
        while let Some(widget) = child {
            child = widget.next_sibling();
            result.extend(descendants(&widget));
            result.push(widget);
        }
        result
    }
    let window = parent
        .application()
        .context("缺少应用")?
        .active_window()
        .context("规则编辑器未打开")?;
    ensure!(
        window.title().as_deref() == Some("编辑规则集"),
        "规则编辑器未打开"
    );
    let widgets = descendants(&window);
    let stack = widgets
        .iter()
        .find(|w| w.widget_name() == "ruleset-tabs")
        .context("缺少规则页签")?
        .clone()
        .downcast::<gtk::Stack>()
        .unwrap();
    let content = stack.child_by_name("content").context("缺少规则内容页")?;
    let interval = widgets
        .iter()
        .filter_map(|w| w.downcast_ref::<adw::SpinRow>())
        .find(|r| r.title() == "自动更新间隔（小时）")
        .context("缺少规则更新间隔")?;
    let source = widgets
        .iter()
        .filter_map(|w| w.downcast_ref::<gtk::Entry>())
        .find(|entry| entry.placeholder_text().as_deref() == Some("在线地址或本地文件"))
        .context("缺少规则来源")?;
    ensure!(
        interval.is_visible() && !stack.page(&content).is_visible(),
        "在线规则显示了无效的本地编辑器"
    );
    let original_source = source.text();
    source.set_text("");
    ensure!(
        !interval.is_visible() && stack.page(&content).is_visible(),
        "本地规则编辑不可用"
    );
    source.set_text(&original_source);
    interval.set_value(12.0);
    let save = widgets
        .iter()
        .filter_map(|w| w.downcast_ref::<gtk::Button>())
        .find(|b| b.label().as_deref() == Some("保存"))
        .context("缺少保存按钮")?;
    save.emit_clicked();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn common_rules_validate_addresses_and_generate_core_fields() {
        assert_eq!(
            common_rule("domain_suffix", ".example.com").unwrap(),
            json!({"domain_suffix":["example.com"]})
        );
        assert_eq!(common_rule("port", "443").unwrap(), json!({"port":[443]}));
        assert_eq!(
            common_rule("ip_cidr", "fe80::/10").unwrap(),
            json!({"ip_cidr":["fe80::/10"]})
        );
        for (kind, invalid) in [
            ("domain", "https://example.com/path"),
            ("port", "65536"),
            ("port", "0"),
            ("ip_cidr", "10.0.0.1/33"),
            ("ip_cidr", "fe80::/129"),
            ("domain", ""),
        ] {
            assert!(common_rule(kind, invalid).is_err());
        }
    }
}
