use std::{cell::Cell, rc::Rc, sync::Arc, time::Duration};

use adw::prelude::*;
use anyhow::{Context, Result, ensure};
use gtk::glib;
use serde_json::{Value, json};
use sourceview::prelude::*;

use crate::{
    engine::Service,
    model::{self, Profile, RuleSet, Subscription},
};

type Saved = Rc<dyn Fn()>;
type SaveText = Box<dyn Fn(String) -> Result<()>>;

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
fn entry(title: &str, text: &str) -> adw::EntryRow {
    let row = adw::EntryRow::builder().title(title).build();
    row.set_text(text);
    row
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
#[derive(Clone, Debug, PartialEq)]
struct CommonFields {
    mixed: bool,
    host: String,
    port: u16,
    dns: String,
    final_outbound: String,
}
impl CommonFields {
    fn from_config(config: &Value) -> Self {
        let inbounds = config["inbounds"].as_array();
        let mixed = inbounds.and_then(|items| items.iter().find(|v| v["type"] == "mixed"));
        let dns = config["dns"]["servers"]
            .as_array()
            .and_then(|servers| servers.first());
        Self {
            mixed: mixed.is_some(),
            host: mixed
                .and_then(|v| v["listen"].as_str())
                .unwrap_or("127.0.0.1")
                .into(),
            port: mixed
                .and_then(|v| v["listen_port"].as_u64())
                .unwrap_or(2080) as u16,
            dns: dns.and_then(|v| v["server"].as_str()).unwrap_or("").into(),
            final_outbound: config["route"]["final"].as_str().unwrap_or("").into(),
        }
    }
}

fn object_child<'a>(value: &'a mut Value, key: &str) -> Result<&'a mut Value> {
    ensure!(value.is_object(), "配置必须是 JSON 对象");
    if value.get(key).is_none() {
        value[key] = json!({});
    }
    ensure!(value[key].is_object(), "{key} 必须是一个对象");
    Ok(&mut value[key])
}
fn apply_common(config: &mut Value, before: &CommonFields, after: &CommonFields) -> Result<()> {
    ensure!(config.is_object(), "配置必须是 JSON 对象");
    if (before.mixed, &before.host, before.port) != (after.mixed, &after.host, after.port) {
        if config.get("inbounds").is_none() {
            config["inbounds"] = json!([]);
        }
        let inbounds = config["inbounds"]
            .as_array_mut()
            .context("入站必须是数组")?;
        if before.mixed != after.mixed || before.host != after.host || before.port != after.port {
            if after.mixed {
                ensure!(!after.host.trim().is_empty(), "监听地址不能为空");
                ensure!(after.port != 0, "监听端口必须介于 1 到 65535");
                let (index, created) =
                    if let Some(index) = inbounds.iter().position(|v| v["type"] == "mixed") {
                        (index, false)
                    } else {
                        inbounds.push(json!({"type":"mixed","tag":"mixed-in"}));
                        (inbounds.len() - 1, true)
                    };
                if created || before.host != after.host {
                    inbounds[index]["listen"] = json!(after.host.trim());
                }
                if created || before.port != after.port {
                    inbounds[index]["listen_port"] = json!(after.port);
                }
            } else {
                inbounds.retain(|v| v["type"] != "mixed");
            }
        }
    }
    if before.final_outbound != after.final_outbound {
        object_child(config, "route")?["final"] = json!(after.final_outbound.trim());
    }
    if before.dns != after.dns {
        let dns = object_child(config, "dns")?;
        if dns.get("servers").is_none() {
            dns["servers"] = json!([]);
        }
        let servers = dns["servers"]
            .as_array_mut()
            .context("DNS 服务器必须是数组")?;
        ensure!(!after.dns.trim().is_empty(), "DNS 地址不能为空");
        if servers.is_empty() {
            servers.push(json!({"type":"udp","tag":"dns-local","server":after.dns.trim()}));
        } else {
            ensure!(servers[0].is_object(), "DNS 服务器必须是对象");
            servers[0]["server"] = json!(after.dns.trim());
        }
    }
    Ok(())
}

pub fn profile(
    parent: &adw::ApplicationWindow,
    service: Arc<Service>,
    item: Profile,
    on_saved: Saved,
) {
    let editor = EditorWindow::new(parent, "编辑配置", "");
    let stack = tabs(&editor.body);
    let (scroll, form) = form_page();
    let initial = CommonFields::from_config(&item.config);

    let basic = group("配置", "");
    let name = entry("名称", &item.name);
    basic.add(&name);
    form.append(&basic);

    let inbound = group("本地代理", "");
    let mixed = switch("混合代理", "", initial.mixed);
    let host = entry("监听地址", &initial.host);
    let port = gtk::SpinButton::with_range(1.0, 65535.0, 1.0);
    port.set_value(initial.port as f64);
    port.set_valign(gtk::Align::Center);
    port.set_width_chars(7);
    let port_row = adw::ActionRow::builder()
        .title("监听端口")
        .activatable_widget(&port)
        .build();
    port_row.add_suffix(&port);
    host.set_sensitive(initial.mixed);
    port_row.set_sensitive(initial.mixed);
    let host_for_toggle = host.clone();
    let port_for_toggle = port_row.clone();
    mixed.connect_active_notify(move |row| {
        host_for_toggle.set_sensitive(row.is_active());
        port_for_toggle.set_sensitive(row.is_active());
    });
    inbound.add(&mixed);
    inbound.add(&host);
    inbound.add(&port_row);
    form.append(&inbound);

    let routing = group("路由与 DNS", "");
    let dns = entry("DNS 服务器", &initial.dns);
    let outbound = entry("默认出口", &initial.final_outbound);
    routing.add(&dns);
    routing.add(&outbound);
    form.append(&routing);
    stack.add_titled(&scroll, Some("general"), "常用设置");

    let (resource_scroll, resources) = form_page();
    let state = service.snapshot();
    let subscriptions = group("订阅", "");
    let mut sub_controls = Vec::new();
    if state.subscriptions.is_empty() {
        subscriptions.add(
            &adw::ActionRow::builder()
                .title("尚未添加订阅")
                .subtitle("")
                .build(),
        );
    }
    for subscription in &state.subscriptions {
        let row = switch(
            &subscription.name,
            &format!("{} 个节点", subscription.nodes.len()),
            item.subscriptions.contains(&subscription.id),
        );
        subscriptions.add(&row);
        sub_controls.push((subscription.id.clone(), row));
    }
    resources.append(&subscriptions);
    let rulesets = group("规则集", "");
    let mut rule_controls = Vec::new();
    if state.rulesets.is_empty() {
        rulesets.add(
            &adw::ActionRow::builder()
                .title("尚未添加规则集")
                .subtitle("")
                .build(),
        );
    }
    for rule in &state.rulesets {
        let row = switch(
            &rule.name,
            if rule.binary {
                "SRS 二进制规则集"
            } else {
                "JSON 源规则集"
            },
            item.rulesets.contains(&rule.id),
        );
        rulesets.add(&row);
        rule_controls.push((rule.id.clone(), row));
    }
    resources.append(&rulesets);
    stack.add_titled(&resource_scroll, Some("resources"), "引用资源");

    let config = SourceEditor::new(
        &model::pretty(&item.config),
        "json",
        true,
        "网络开关在应用设置中统一管理",
    );
    let config_tools = gtk::Box::new(gtk::Orientation::Horizontal, 8);
    let format = gtk::Button::with_label("格式化 JSON");
    format.add_css_class("compact-action");
    let config_buffer = config.buffer.clone();
    let error_for_format = editor.error.clone();
    format.connect_clicked(move |_| match parse_json_buffer(&config_buffer) {
        Ok(value) => {
            config_buffer.set_text(&model::pretty(&value));
            error_for_format.set_visible(false);
        }
        Err(err) => show_error(&error_for_format, err),
    });
    config_tools.append(&format);
    config.root.prepend(&config_tools);
    stack.add_titled(&config.root, Some("config"), "配置 JSON");
    let script = SourceEditor::new(&item.script, "js", true, "onGenerate(config) → config");
    stack.add_titled(&script.root, Some("script"), "生成脚本");

    let read_draft: Rc<dyn Fn() -> Result<Profile>> = Rc::new(move || {
        ensure!(!name.text().trim().is_empty(), "请填写配置名称");
        let mut value = parse_json_buffer(&config.buffer)?;
        let common = CommonFields {
            mixed: mixed.is_active(),
            host: host.text().into(),
            port: port.value_as_int() as u16,
            dns: dns.text().into(),
            final_outbound: outbound.text().into(),
        };
        apply_common(&mut value, &initial, &common)?;
        let mut next = item.clone();
        next.name = name.text().trim().into();
        next.config = value;
        next.subscriptions = sub_controls
            .iter()
            .filter(|(_, r)| r.is_active())
            .map(|(id, _)| id.clone())
            .collect();
        next.rulesets = rule_controls
            .iter()
            .filter(|(_, r)| r.is_active())
            .map(|(id, _)| id.clone())
            .collect();
        next.script = script.text();
        Ok(next)
    });
    let preview = gtk::Button::with_label("预览生成结果");
    let check = gtk::Button::with_label("检查配置");
    for (button, check_core) in [(&preview, false), (&check, true)] {
        button.add_css_class("compact-action");
        let service = service.clone();
        let read_draft = read_draft.clone();
        let weak_window = editor.window.downgrade();
        let error = editor.error.clone();
        button.connect_clicked(move |button| {
            let draft = match read_draft() {
                Ok(draft) => draft,
                Err(e) => {
                    show_error(&error, e);
                    return;
                }
            };
            error.set_visible(false);
            button.set_sensitive(false);
            let idle_label = if check_core {
                "检查配置"
            } else {
                "预览生成结果"
            };
            button.set_label(if check_core {
                "检查中…"
            } else {
                "生成中…"
            });
            let state = service.snapshot();
            let work = service.clone();
            let (send, recv) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let result = work.generate_profile(&state, &draft).and_then(|config| {
                    if check_core {
                        work.check(&config)?;
                    }
                    Ok(config)
                });
                let _ = send.send(result);
            });
            let weak_window = weak_window.clone();
            let error = error.clone();
            let button = button.clone();
            glib::timeout_add_local(Duration::from_millis(30), move || {
                if weak_window.upgrade().is_none() {
                    return glib::ControlFlow::Break;
                }
                match recv.try_recv() {
                    Ok(result) => {
                        button.set_sensitive(true);
                        button.set_label(idle_label);
                        match result {
                            Ok(config) => {
                                if let Some(window) = weak_window.upgrade() {
                                    code(
                                        &window,
                                        if check_core {
                                            "检查通过 · 生成的配置"
                                        } else {
                                            "生成的配置"
                                        },
                                        &model::pretty(&config),
                                        "json",
                                        None,
                                    );
                                }
                            }
                            Err(e) => show_error(&error, e),
                        }
                        glib::ControlFlow::Break
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
                    Err(_) => {
                        button.set_sensitive(true);
                        button.set_label(idle_label);
                        show_error(&error, "配置处理任务意外结束");
                        glib::ControlFlow::Break
                    }
                }
            });
        });
        config_tools.append(button);
    }
    let weak_window = editor.window.downgrade();
    let error = editor.error.clone();
    editor.save.connect_clicked(move |_| {
        let result = read_draft().and_then(|next| {
            service.update(|state| {
                if let Some(old) = state.profiles.iter_mut().find(|p| p.id == next.id) {
                    *old = next;
                } else {
                    state.profiles.push(next);
                }
                Ok(())
            })
        });
        match result {
            Ok(()) => {
                on_saved();
                if let Some(w) = weak_window.upgrade() {
                    w.close();
                }
            }
            Err(err) => show_error(&error, err),
        }
    });
    editor.window.present();
}

pub fn subscription(
    parent: &adw::ApplicationWindow,
    service: Arc<Service>,
    item: Subscription,
    on_saved: Saved,
) {
    let editor = EditorWindow::new(parent, "编辑订阅", "");
    let stack = tabs(&editor.body);
    let (scroll, form) = form_page();
    let source_group = group("订阅来源", "");
    let name = entry("名称", &item.name);
    let source = entry("订阅地址或文件路径", &item.source);
    source.set_tooltip_text(Some("留空可手动添加节点"));
    let choose = gtk::Button::from_icon_name("document-open-symbolic");
    choose.set_tooltip_text(Some("选择本地订阅文件"));
    choose.add_css_class("flat");
    source.add_suffix(&choose);
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
    source_group.add(&name);
    source_group.add(&source);
    form.append(&source_group);
    let filters = group("筛选节点", "");
    let include = entry("包含名称（正则）", &item.include);
    let exclude = entry("排除名称（正则）", &item.exclude);
    let prefix = entry("名称前缀", &item.prefix);
    filters.add(&include);
    filters.add(&exclude);
    filters.add(&prefix);
    form.append(&filters);
    stack.add_titled(&scroll, Some("source"), "订阅设置");
    let script = SourceEditor::new(&item.script, "js", true, "onSubscribe(nodes) → nodes");
    stack.add_titled(&script.root, Some("script"), "处理脚本");
    let weak = editor.window.downgrade();
    let error = editor.error.clone();
    editor.save.connect_clicked(move |_| {
        let result = (|| -> Result<()> {
            ensure!(!name.text().trim().is_empty(), "请填写订阅名称");
            for (label, value) in [("包含名称", include.text()), ("排除名称", exclude.text())]
            {
                if !value.is_empty() {
                    regex::Regex::new(&value)
                        .with_context(|| format!("{label}的正则表达式无效"))?;
                }
            }
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
                next.source = source.text().trim().into();
                next.include = include.text().into();
                next.exclude = exclude.text().into();
                next.prefix = prefix.text().into();
                next.script = script.text();
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

pub fn ruleset(
    parent: &adw::ApplicationWindow,
    service: Arc<Service>,
    item: RuleSet,
    on_saved: Saved,
) {
    let editor = EditorWindow::new(parent, "编辑规则集", "");
    let stack = tabs(&editor.body);
    let (scroll, form) = form_page();
    let basic = group("规则集", "");
    let name = entry("名称", &item.name);
    let source = entry("更新地址或文件路径", &item.source);
    let format_model = gtk::StringList::new(&["JSON 源文件", "SRS 二进制文件"]);
    let format = adw::ComboRow::builder()
        .title("文件格式")
        .model(&format_model)
        .selected(u32::from(item.binary))
        .build();
    basic.add(&name);
    basic.add(&source);
    basic.add(&format);
    form.append(&basic);
    stack.add_titled(&scroll, Some("general"), "基本信息");
    let content = SourceEditor::new(
        &model::pretty(&item.content),
        "json",
        true,
        "远程更新会替换规则内容",
    );
    stack.add_titled(&content.root, Some("content"), "规则内容");
    let content_for_format = content.root.clone();
    content_for_format.set_sensitive(!item.binary);
    format
        .connect_selected_notify(move |row| content_for_format.set_sensitive(row.selected() == 0));
    let weak = editor.window.downgrade();
    let error = editor.error.clone();
    editor.save.connect_clicked(move |_| {
        let result = (|| -> Result<()> {
            ensure!(!name.text().trim().is_empty(), "请填写规则集名称");
            let binary = format.selected() == 1;
            let value = if !binary {
                let value = parse_json_buffer(&content.buffer)?;
                validate_rules(&value)?;
                Some(value)
            } else {
                None
            };
            service.update(|state| {
                let mut next = state
                    .rulesets
                    .iter()
                    .find(|r| r.id == item.id)
                    .cloned()
                    .unwrap_or_else(|| item.clone());
                let previous_name = next.name.clone();
                next.name = name.text().trim().into();
                next.source = source.text().trim().into();
                next.binary = binary;
                // A completed background update stays intact when only metadata
                // was edited. Explicit content edits remain authoritative.
                if let Some(value) = value
                    && (item.binary || value != item.content)
                {
                    next.content = value;
                }
                model::rename_rule_references(state, &next.id, &previous_name, &next.name);
                if let Some(old) = state.rulesets.iter_mut().find(|r| r.id == next.id) {
                    *old = next;
                } else {
                    state.rulesets.push(next);
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

pub fn nodes(
    parent: &adw::ApplicationWindow,
    service: Arc<Service>,
    item: Subscription,
    on_saved: Saved,
) {
    code(
        parent,
        &format!("{} · 节点", item.name),
        &model::pretty(&item.nodes),
        "json",
        Some(Box::new(move |text| {
            let nodes = aerobox_for_linux::subscription::parse(&text)?;
            service.update(|state| {
                let current = state
                    .subscriptions
                    .iter_mut()
                    .find(|s| s.id == item.id)
                    .context("订阅已被删除")?;
                current.nodes = nodes;
                Ok(())
            })?;
            on_saved();
            Ok(())
        })),
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
                    .initial_name(format!("AeroBox.{}", if ext == "js" { "js" } else { &ext }))
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
    if let Some(save) = on_save {
        editor
            .save
            .connect_clicked(move |_| match save(source.text()) {
                Ok(()) => {
                    if let Some(w) = weak.upgrade() {
                        w.close();
                    }
                }
                Err(e) => show_error(&err, e),
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
            Some(Box::new(move |text| {
                let value: Value = serde_json::from_str(&text)?;
                validate_rules(&value)?;
                service.update(|state| {
                    let rule = state
                        .rulesets
                        .iter_mut()
                        .find(|r| r.id == item.id)
                        .context("规则集已被删除")?;
                    rule.content = value;
                    Ok(())
                })?;
                on_saved();
                Ok(())
            })),
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

/// Exercises real GTK controls during the opt-in Wayland smoke run.
pub(super) fn smoke_profile(parent: &adw::ApplicationWindow, service: Arc<Service>) -> Result<()> {
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
    fn button(widgets: &[gtk::Widget], label: &str) -> Result<gtk::Button> {
        widgets
            .iter()
            .filter_map(|w| w.clone().downcast::<gtk::Button>().ok())
            .find(|b| b.label().as_deref() == Some(label))
            .with_context(|| format!("找不到{label}按钮"))
    }
    let app = parent.application().context("缺少应用")?;
    let window = app.active_window().context("配置编辑器未打开")?;
    ensure!(
        window != parent.clone().upcast::<gtk::Window>(),
        "配置编辑器未打开"
    );
    let widgets = descendants(&window);
    let name = widgets
        .iter()
        .filter_map(|w| w.clone().downcast::<adw::EntryRow>().ok())
        .find(|row| row.title() == "名称")
        .context("缺少名称输入")?;
    let host = widgets
        .iter()
        .filter_map(|w| w.clone().downcast::<adw::EntryRow>().ok())
        .find(|row| row.title() == "监听地址")
        .context("缺少监听地址输入")?;
    let buffer = widgets
        .iter()
        .filter_map(|w| w.clone().downcast::<sourceview::View>().ok())
        .filter_map(|view| view.buffer().downcast::<sourceview::Buffer>().ok())
        .find(|buffer| buffer.language().is_some_and(|lang| lang.id() == "json"))
        .context("缺少配置 JSON 编辑器")?;
    let before = service.snapshot();
    let original = before
        .profiles
        .iter()
        .find(|p| p.name == name.text())
        .context("找不到测试配置")?;
    let save = button(&widgets, "保存")?;
    buffer.set_text("{");
    name.set_text("冒烟测试 · 当前草稿");
    save.emit_clicked();
    ensure!(window.is_visible(), "无效 JSON 意外关闭了编辑器");
    ensure!(
        serde_json::to_value(&before)? == serde_json::to_value(service.snapshot())?,
        "无效 JSON 被保存"
    );
    ensure!(
        widgets
            .iter()
            .any(|w| w.has_css_class("error") && w.is_visible()),
        "缺少 JSON 错误提示"
    );
    let mut config = original.config.clone();
    config["inbounds"][0]["listen_port"] = json!(17777);
    config["route"]["final"] = json!("direct");
    buffer.set_text(&model::pretty(&config));
    host.set_text("127.0.0.2");
    save.emit_clicked();
    let after = service.snapshot();
    let saved = after
        .profiles
        .iter()
        .find(|p| p.id == original.id)
        .context("配置未保存")?;
    ensure!(saved.name == "冒烟测试 · 当前草稿", "保存没有使用当前名称");
    ensure!(
        saved.config["inbounds"][0]["listen"] == "127.0.0.2",
        "保存没有使用当前监听地址"
    );
    ensure!(
        saved.config["inbounds"][0]["listen_port"] == 17777,
        "保存覆盖了 JSON 中的监听端口"
    );
    ensure!(
        saved.config["route"]["final"] == "direct",
        "保存覆盖了 JSON 中的默认出口"
    );
    let draft = Profile::new("取消后不应存在");
    let draft_id = draft.id.clone();
    profile(parent, service.clone(), draft, Rc::new(|| {}));
    let cancel_window = app
        .windows()
        .into_iter()
        .find(|w| w.is_visible() && *w != parent.clone().upcast::<gtk::Window>())
        .context("取消测试编辑器未打开")?;
    button(&descendants(&cancel_window), "取消")?.emit_clicked();
    ensure!(
        !service.snapshot().profiles.iter().any(|p| p.id == draft_id),
        "取消操作写入了配置"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unchanged_form_preserves_manual_json() {
        let original = Profile::new("test").config;
        let initial = CommonFields::from_config(&original);
        let mut changed = original.clone();
        changed["inbounds"][0]["listen_port"] = json!(7777);
        changed["dns"]["servers"][0]["server"] = json!("1.1.1.1");
        changed["future"] = json!({"unknown":true});
        let expected = changed.clone();
        apply_common(&mut changed, &initial, &initial).unwrap();
        assert_eq!(changed, expected);
    }
    #[test]
    fn edit_preserves_advanced_inbound_fields() {
        let mut config = Profile::new("test").config;
        config["inbounds"][0]["users"] = json!([{"username":"u","password":"p"}]);
        let before = CommonFields::from_config(&config);
        let mut after = before.clone();
        after.port = 1080;
        apply_common(&mut config, &before, &after).unwrap();
        assert_eq!(config["inbounds"][0]["listen_port"], 1080);
        assert_eq!(config["inbounds"][0]["users"][0]["password"], "p");
    }
    #[test]
    fn changed_host_preserves_port_edited_as_json() {
        let mut config = Profile::new("test").config;
        let before = CommonFields::from_config(&config);
        let mut after = before.clone();
        after.host = "0.0.0.0".into();
        config["inbounds"][0]["listen_port"] = json!(7777);
        apply_common(&mut config, &before, &after).unwrap();
        assert_eq!(config["inbounds"][0]["listen"], "0.0.0.0");
        assert_eq!(config["inbounds"][0]["listen_port"], 7777);
    }
    #[test]
    fn malformed_sections_fail_without_panic() {
        let original = Profile::new("test").config;
        let before = CommonFields::from_config(&original);
        let mut after = before.clone();
        after.port = 1080;
        let mut config = json!({"inbounds":"broken"});
        assert!(apply_common(&mut config, &before, &after).is_err());
    }
}
