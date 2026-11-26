use super::*;
use aerobox_for_linux::model::Subscription;
use anyhow::ensure;
use serde_json::json;
use sourceview::prelude::*;

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
        let dialog = dialog_header(parent, title, "保存", "object-select-symbolic", 880, 740);
        let window = dialog.window;
        let root = dialog.root;
        let cancel = dialog.cancel;
        let save = dialog.action;
        let saving = Rc::new(Cell::new(false));
        let guard = saving.clone();
        window.connect_close_request(move |_| {
            if guard.get() {
                glib::Propagation::Stop
            } else {
                glib::Propagation::Proceed
            }
        });
        dialog
            .header
            .set_title_widget(Some(&adw::WindowTitle::new(title, subtitle)));
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
        error.set_widget_name("editor-error");
        error.add_css_class("error");
        error.add_css_class("dialog-error");
        root.append(&error);
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
    let form = gtk::Box::new(gtk::Orientation::Vertical, 20);
    form.add_css_class("dialog-form");
    form.set_valign(gtk::Align::Start);
    form.set_margin_top(16);
    form.set_margin_bottom(24);
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
    let fields = gtk::Box::new(gtk::Orientation::Vertical, 0);
    fields.add_css_class("dialog-fields");
    let name = LabeledEntry::new("名称", &item.name);
    let source = LabeledEntry::new("订阅地址或文件路径", &item.source);
    source.entry.set_tooltip_text(Some("留空可手动添加节点"));
    let choose = gtk::Button::from_icon_name("document-open-symbolic");
    choose.set_tooltip_text(Some("选择本地订阅文件"));
    choose.add_css_class("flat");
    source.with_suffix(&choose);
    let source_for_file = source.entry.downgrade();
    let weak = editor.window.downgrade();
    choose.connect_clicked(move |_| {
        if let (Some(parent), Some(source)) = (weak.upgrade(), source_for_file.upgrade()) {
            glib::MainContext::default().spawn_local(async move {
                if let Ok(file) = gtk::FileDialog::new().open_future(Some(&parent)).await
                    && let Some(path) = file.path()
                {
                    source.set_text(&path.to_string_lossy());
                }
            });
        }
    });
    fields.append(&name.root);
    fields.append(&source.root);
    form.append(&fields);
    let updates = gtk::Box::new(gtk::Orientation::Vertical, 12);
    updates.set_visible(!item.source.is_empty());
    let update_group = group("更新设置", "");
    let auto_update = switch("自动更新", "", item.auto_update);
    let interval = number_entry(
        "更新间隔（分钟）",
        &item.update_interval_minutes.to_string(),
    );
    interval.root.set_sensitive(item.auto_update);
    let interval_toggle = interval.root.clone();
    auto_update.connect_active_notify(move |row| interval_toggle.set_sensitive(row.is_active()));
    update_group.add(&auto_update);
    updates.append(&update_group);
    updates.append(&interval.root);
    form.append(&updates);
    let updates = updates.downgrade();
    source.entry.connect_changed(move |source| {
        if let Some(updates) = updates.upgrade() {
            updates.set_visible(!source.text().trim().is_empty());
        }
    });
    let edit_nodes = toolbar_action("编辑节点数据");
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
    let saving = editor.saving.clone();
    let cancel = editor.cancel.downgrade();
    let body = editor.body.downgrade();
    editor.save.connect_clicked(move |button| {
        if saving.replace(true) {
            return;
        }
        error.set_visible(false);
        let original_button = button.child();
        let spinner = gtk::Spinner::builder().spinning(true).build();
        let progress = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        progress.append(&spinner);
        progress.append(&gtk::Label::new(Some("保存中…")));
        button.set_child(Some(&progress));
        button.set_sensitive(false);
        if let Some(cancel) = cancel.upgrade() {
            cancel.set_sensitive(false);
        }
        if let Some(body) = body.upgrade() {
            body.set_sensitive(false);
        }
        let service = service.clone();
        let original = item.clone();
        let name = name.text().trim().to_owned();
        let input = source.text().trim().to_owned();
        let auto_update = auto_update.is_active();
        let update_interval_minutes = interval.text().trim().parse().unwrap_or(0);
        let saving = saving.clone();
        let button = button.downgrade();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = (|| -> Result<()> {
                ensure!(!name.is_empty(), "请填写订阅名称");
                let mut next = original.clone();
                next.name = name;
                let updated_source = if input.contains("://") {
                    let parsed = aerobox_for_linux::subscription::import_input(&input)?;
                    ensure!(!parsed.source.is_empty(), "这里需要订阅地址");
                    parsed.source
                } else {
                    input
                };
                next.source = updated_source;
                next.auto_update = auto_update && !next.source.is_empty();
                next.update_interval_minutes = update_interval_minutes;
                service.save_subscription(&original, next)
            })();
            let _ = tx.send(result);
        });
        let weak = weak.clone();
        let saving = saving.clone();
        let error = error.clone();
        let cancel = cancel.clone();
        let body = body.clone();
        let on_saved = on_saved.clone();
        glib::timeout_add_local(Duration::from_millis(40), move || {
            let result = match rx.try_recv() {
                Ok(result) => result,
                Err(mpsc::TryRecvError::Empty) => {
                    return if weak.upgrade().is_some() {
                        glib::ControlFlow::Continue
                    } else {
                        glib::ControlFlow::Break
                    };
                }
                Err(_) => Err(anyhow::anyhow!("保存任务意外结束")),
            };
            let Some(window) = weak.upgrade() else {
                return glib::ControlFlow::Break;
            };
            saving.set(false);
            spinner.stop();
            if let Some(button) = button.upgrade() {
                button.set_child(original_button.as_ref());
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
                    window.close();
                }
                Err(error_text) => show_error(&error, error_text),
            }
            glib::ControlFlow::Break
        });
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
        "domain_keyword" => json!([value]),
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
    let is_new = !service
        .snapshot()
        .rulesets
        .iter()
        .any(|rule| rule.id == item.id);
    let editor = EditorWindow::new(
        parent,
        if is_new {
            "导入规则"
        } else {
            "编辑规则"
        },
        "",
    );
    editor.window.set_default_size(
        if is_new { 560 } else { 880 },
        if is_new { 570 } else { 740 },
    );
    if is_new {
        editor.save.set_widget_name("rule-import-save");
        update_action(&editor.save, "document-save-symbolic", "导入");
    }
    let stack = tabs(&editor.body);
    let switcher = stack.prev_sibling().expect("editor tabs");
    stack.set_widget_name("ruleset-tabs");
    let (scroll, form) = form_page();
    let name = LabeledEntry::new("名称", &item.name);
    name.entry.set_widget_name("rule-name");
    let source = LabeledEntry::new("规则链接或本地文件", &item.source);
    source.entry.set_widget_name("rule-source");
    let source_section = gtk::Box::new(gtk::Orientation::Vertical, 0);
    source_section.add_css_class("dialog-fields");
    source_section.append(&name.root);
    source_section.append(&source.root);
    form.append(&source_section);
    let updates = gtk::Box::new(gtk::Orientation::Vertical, 12);
    let format_group = group("来源与格式", "");
    let options = group("规则选项", "");
    let interval = number_entry(
        "自动更新间隔（分钟）",
        &item.update_interval_minutes.to_string(),
    );
    interval.root.set_visible(item.is_remote());
    let format_model = gtk::StringList::new(&["JSON 源文件", "SRS 二进制文件"]);
    let format = adw::ComboRow::builder()
        .title("文件格式")
        .model(&format_model)
        .selected(u32::from(item.binary))
        .build();
    format_group.add(&format);
    updates.append(&format_group);
    updates.append(&interval.root);
    form.append(&updates);
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
    options.add(&action);
    options.add(&enabled);
    form.append(&options);
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
        "port",
    ];
    let kind = gtk::DropDown::from_strings(&["域名", "域名后缀", "域名关键字", "IP 网段", "端口"]);
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
    stack.add_titled(&rules, Some("content"), "规则内容");
    let refresh_source = {
        let stack = stack.downgrade();
        let switcher = switcher.downgrade();
        let interval = interval.root.downgrade();
        let source = source.entry.downgrade();
        let format = format.downgrade();
        Rc::new(move || {
            let (Some(stack), Some(switcher), Some(interval), Some(source), Some(format)) = (
                stack.upgrade(),
                switcher.upgrade(),
                interval.upgrade(),
                source.upgrade(),
                format.upgrade(),
            ) else {
                return;
            };
            let source = source.text();
            let inline = source.trim().is_empty() && format.selected() == 0;
            interval.set_visible(model::is_online_source(source.trim()));
            let content = stack.child_by_name("content").expect("rule content");
            if !inline {
                stack.set_visible_child_name("general");
            }
            stack.page(&content).set_visible(inline);
            switcher.set_visible(inline);
        })
    };
    refresh_source();
    let refresh = refresh_source.clone();
    source.entry.connect_changed(move |_| refresh());
    format.connect_selected_notify(move |_| refresh_source());
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
            ensure!(!name.text().trim().is_empty(), "请填写规则名称");
            let binary = format.selected() == 1;
            let source_text = source.text().trim().to_owned();
            let value = if !binary && source_text.is_empty() {
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
                .find(|rule| rule.id == item.id)
                .unwrap_or_else(|| item.clone());
            next.name = name.text().trim().into();
            next.source = source_text;
            if model::is_online_source(&next.source) {
                next.update_interval_minutes = interval
                    .text()
                    .trim()
                    .parse()
                    .context("请填写有效的更新间隔")?;
            }
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
                let original = button.child();
                let spinner = gtk::Spinner::new();
                spinner.start();
                let progress = gtk::Box::new(gtk::Orientation::Horizontal, 8);
                progress.append(&spinner);
                progress.append(&gtk::Label::new(Some(if is_new {
                    "导入中…"
                } else {
                    "保存中…"
                })));
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
                            return if weak.upgrade().is_some() {
                                glib::ControlFlow::Continue
                            } else {
                                glib::ControlFlow::Break
                            };
                        }
                        Err(_) => Err(anyhow::anyhow!("保存任务意外结束")),
                    };
                    saving.set(false);
                    spinner.stop();
                    if let Some(button) = button.upgrade() {
                        button.set_child(original.as_ref());
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
    editor.body.append(&source.root);
    let weak = editor.window.downgrade();
    let err = editor.error.clone();
    if let Some((save, on_saved)) = on_save {
        let saving = editor.saving.clone();
        let cancel = editor.cancel.downgrade();
        let body = editor.body.downgrade();
        editor.save.connect_clicked(move |button| {
            if saving.replace(true) {
                return;
            }
            err.set_visible(false);
            let original = button.child();
            let progress = gtk::Box::new(gtk::Orientation::Horizontal, 8);
            let spinner = gtk::Spinner::builder().spinning(true).build();
            progress.append(&spinner);
            progress.append(&gtk::Label::new(Some("保存中…")));
            button.set_child(Some(&progress));
            button.set_sensitive(false);
            if let Some(cancel) = cancel.upgrade() {
                cancel.set_sensitive(false);
            }
            if let Some(body) = body.upgrade() {
                body.set_sensitive(false);
            }
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
                        return if weak.upgrade().is_some() {
                            glib::ControlFlow::Continue
                        } else {
                            glib::ControlFlow::Break
                        };
                    }
                    Err(_) => Err(anyhow::anyhow!("保存任务意外结束")),
                };
                saving.set(false);
                spinner.stop();
                button.set_child(original.as_ref());
                button.set_sensitive(true);
                if let Some(cancel) = cancel.upgrade() {
                    cancel.set_sensitive(true);
                }
                if let Some(body) = body.upgrade() {
                    body.set_sensitive(true);
                }
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
        update_action(&editor.save, "object-select-symbolic", "完成");
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
    let editor = EditorWindow::new(parent, &format!("{} · 规则", item.name), "");
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
                        let source =
                            SourceEditor::new(&text, "json", true, "修改后保存为 JSON 规则。");
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
                            let original = button.child();
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
                            let error_label = error.clone();
                            let button = button.downgrade();
                            let cancel = cancel.downgrade();
                            let source_root = source.root.downgrade();
                            let saving = saving.clone();
                            let on_saved = on_saved.clone();
                            glib::timeout_add_local(Duration::from_millis(30), move || {
                                let result = match recv.try_recv() {
                                    Ok(result) => result,
                                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                                        return if weak.upgrade().is_some() {
                                            glib::ControlFlow::Continue
                                        } else {
                                            glib::ControlFlow::Break
                                        };
                                    }
                                    Err(_) => Err(anyhow::anyhow!("保存任务意外结束")),
                                };
                                let Some(window) = weak.upgrade() else {
                                    return glib::ControlFlow::Break;
                                };
                                saving.set(false);
                                if let Some(button) = button.upgrade() {
                                    button.set_sensitive(true);
                                    button.set_child(original.as_ref());
                                }
                                if let Some(cancel) = cancel.upgrade() {
                                    cancel.set_sensitive(true);
                                }
                                if let Some(source_root) = source_root.upgrade() {
                                    source_root.set_sensitive(true);
                                }
                                match result {
                                    Ok(()) => {
                                        on_saved();
                                        window.close();
                                    }
                                    Err(error) => show_error(&error_label, error),
                                }
                                glib::ControlFlow::Break
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
        "规则需要包含 rules 数组"
    );
    ensure!(value["version"].as_u64().is_some(), "规则需要填写 version");
    Ok(())
}

#[cfg(feature = "ui-smoke")]
pub(super) fn smoke_rule_import(parent: &adw::ApplicationWindow) -> Result<gtk::Window> {
    let window = parent
        .application()
        .context("缺少应用")?
        .windows()
        .into_iter()
        .find(|window| window.title().as_deref() == Some("导入规则"))
        .context("导入规则窗口未打开")?;
    ensure!(
        window.title().as_deref() == Some("导入规则"),
        "导入规则窗口标题错误: {:?}",
        window.title()
    );
    let widgets = descendants(&window);
    let source = widgets
        .iter()
        .find(|widget| widget.widget_name() == "rule-source")
        .context("缺少规则来源")?
        .downcast_ref::<gtk::Entry>()
        .context("规则来源不是输入框")?;
    let stack = widgets
        .iter()
        .find(|widget| widget.widget_name() == "ruleset-tabs")
        .context("缺少规则页签")?
        .downcast_ref::<gtk::Stack>()
        .context("规则页签类型错误")?;
    let switcher = widgets
        .iter()
        .find_map(|widget| widget.downcast_ref::<gtk::StackSwitcher>())
        .context("缺少本地规则编辑入口")?;
    ensure!(switcher.is_visible(), "本地规则无法切换到内容编辑");
    stack.set_visible_child_name("content");
    source.set_text("https://example.test/rules.json");
    ensure!(
        stack.visible_child_name().as_deref() == Some("general") && !switcher.is_visible(),
        "切换在线来源后仍停留在内容编辑页"
    );
    let action = widgets
        .iter()
        .find(|widget| widget.widget_name() == "rule-import-save")
        .context("缺少规则导入按钮")?
        .clone()
        .downcast::<gtk::Button>()
        .unwrap();
    ensure!(
        action.has_css_class("suggested-action") && !action.has_css_class("secondary-action"),
        "规则导入不是主操作"
    );
    for (name, value) in [
        ("rule-name", "导入规则预览"),
        ("rule-source", "https://example.test/rules.json"),
    ] {
        let entry = widgets
            .iter()
            .find(|widget| widget.widget_name() == name)
            .with_context(|| format!("缺少{name}"))?
            .clone()
            .downcast::<gtk::Entry>()
            .unwrap();
        entry.set_text(value);
    }
    ensure!(
        widgets
            .iter()
            .filter_map(|widget| widget.downcast_ref::<gtk::StackSwitcher>())
            .all(|switcher| !switcher.is_visible()),
        "在线规则导入仍显示页签"
    );
    Ok(window)
}

#[cfg(feature = "ui-smoke")]
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
                && rule.update_interval_minutes == 120
                && rule.action == "direct"
                && rule.enabled,
            "规则保存没有生效"
        );
        return Ok(());
    }
    let window = parent
        .application()
        .context("缺少应用")?
        .active_window()
        .context("规则编辑器未打开")?;
    ensure!(
        window.title().as_deref() == Some("编辑规则"),
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
        .filter_map(|w| w.downcast_ref::<gtk::Entry>())
        .find(|entry| entry.placeholder_text().as_deref() == Some("自动更新间隔（分钟）"))
        .context("缺少规则更新间隔")?;
    let source = widgets
        .iter()
        .filter_map(|w| w.downcast_ref::<gtk::Entry>())
        .find(|entry| entry.widget_name() == "rule-source")
        .context("缺少规则来源")?;
    ensure!(
        WidgetExt::is_visible(interval) && !stack.page(&content).is_visible(),
        "在线规则显示了无效的本地编辑器"
    );
    let original_source = source.text();
    let format = widgets
        .iter()
        .find_map(|widget| {
            widget
                .downcast_ref::<adw::ComboRow>()
                .filter(|row| row.title() == "文件格式")
        })
        .context("缺少规则格式")?;
    let original_format = format.selected();
    source.set_text("");
    format.set_selected(0);
    ensure!(
        !WidgetExt::is_visible(interval) && stack.page(&content).is_visible(),
        "本地规则编辑不可用"
    );
    source.set_text(&original_source);
    format.set_selected(original_format);
    interval.set_text("120");
    let save = widgets
        .iter()
        .find(|w| w.widget_name() == "dialog-action")
        .context("缺少保存按钮")?
        .downcast_ref::<gtk::Button>()
        .context("保存控件不是按钮")?;
    ensure!(
        descendants(save)
            .iter()
            .filter_map(|widget| widget.downcast_ref::<gtk::Label>())
            .any(|label| label.label() == "保存"),
        "保存按钮缺少文字"
    );
    ensure!(
        save.has_css_class("suggested-action") && !save.has_css_class("secondary-action"),
        "弹窗保存按钮不应显示为次操作"
    );
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
