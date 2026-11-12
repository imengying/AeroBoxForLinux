use super::*;

pub(super) struct SettingsPanel {
    save: gtk::Button,
    stack: gtk::Stack,
    tabs: gtk::StackSwitcher,
    dirty: gtk::Label,
    read: Rc<dyn Fn() -> (model::Settings, bool)>,
    baseline: RefCell<(model::Settings, bool)>,
    is_dirty: Cell<bool>,
    saving: Cell<bool>,
}

impl SettingsPanel {
    fn save(self: &Rc<Self>, ui: &Rc<Ui>) {
        if self.saving.get() || !self.is_dirty.get() {
            return;
        }
        let after = ui.pending_leave.take();
        let (next, login) = (self.read)();
        if let Err(error) = next.validate() {
            ui.pending_leave.replace(after);
            ui.error("设置无效", error);
            return;
        }
        let valid_url = url::Url::parse(&next.test_url)
            .is_ok_and(|url| matches!(url.scheme(), "http" | "https") && url.host().is_some());
        if !valid_url {
            ui.pending_leave.replace(after);
            ui.error("设置无效", "测速地址须为 HTTP 或 HTTPS 地址");
            return;
        }
        self.saving.set(true);
        self.stack.set_sensitive(false);
        self.tabs.set_sensitive(false);
        let weak = Rc::downgrade(self);
        ui.button_task(
            &self.save,
            "保存中…",
            move |service| {
                service
                    .apply_settings(next)
                    .and_then(|_| platform::set_autostart(login))
            },
            move |ui, result| {
                let Some(panel) = weak.upgrade() else {
                    ui.pending_leave.replace(after);
                    return;
                };
                panel.saving.set(false);
                panel.stack.set_sensitive(true);
                panel.tabs.set_sensitive(true);
                match result {
                    Ok(()) => {
                        panel.is_dirty.set(false);
                        panel.dirty.set_visible(false);
                        panel.save.set_sensitive(false);
                        panel
                            .baseline
                            .replace((ui.service.snapshot().settings, login));
                        ui.notify("设置已保存");
                        if let Some(after) = after {
                            after();
                        } else {
                            ui.refresh(Page::Settings);
                        }
                    }
                    Err(error) => {
                        panel.is_dirty.set(true);
                        panel.dirty.set_visible(true);
                        panel.save.set_sensitive(true);
                        ui.pending_leave.take();
                        ui.error("保存失败", format!("{error:#}"));
                    }
                }
            },
        );
    }

    fn update_dirty(&self) {
        let current = (self.read)();
        let dirty = current != *self.baseline.borrow();
        self.is_dirty.set(dirty);
        self.dirty.set_visible(dirty);
        self.save.set_sensitive(dirty && !self.saving.get());
    }

    pub(super) fn confirm_leave(self: &Rc<Self>, ui: &Rc<Ui>, leave: Rc<dyn Fn()>) -> bool {
        if self.saving.get() || ui.settings_prompt.borrow().is_some() {
            return false;
        }
        if !self.is_dirty.get() {
            return true;
        }
        ui.pending_leave.replace(Some(leave));
        let dialog = adw::AlertDialog::new(
            Some("保存设置更改？"),
            Some("当前设置尚未保存。保存后离开，或放弃本次修改。"),
        );
        dialog.add_response("cancel", "继续编辑");
        dialog.add_response("discard", "放弃更改");
        dialog.add_response("save", "保存并离开");
        dialog.set_response_appearance("discard", adw::ResponseAppearance::Destructive);
        dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);
        dialog.set_default_response(Some("save"));
        dialog.set_close_response("cancel");
        let weak = Rc::downgrade(self);
        let weak_ui = Rc::downgrade(ui);
        dialog.connect_response(None, move |_: &adw::AlertDialog, response| {
            let (Some(panel), Some(ui)) = (weak.upgrade(), weak_ui.upgrade()) else {
                return;
            };
            ui.settings_prompt.take();
            match response {
                "discard" => {
                    let settings = panel.saved_settings();
                    ui.apply_font_size(settings.font_size, settings.crisp_text);
                    apply_theme(&settings.theme);
                    panel.is_dirty.set(false);
                    if let Some(after) = ui.pending_leave.take() {
                        after();
                    }
                }
                "save" => {
                    panel.save(&ui);
                }
                _ => {
                    ui.pending_leave.take();
                }
            }
        });
        dialog.present(Some(&ui.window));
        ui.settings_prompt.replace(Some(dialog.clone()));
        let weak_ui = Rc::downgrade(ui);
        dialog.connect_closed(move |dialog| {
            if let Some(ui) = weak_ui.upgrade()
                && ui
                    .settings_prompt
                    .borrow()
                    .as_ref()
                    .is_some_and(|current| current == dialog)
            {
                ui.settings_prompt.take();
                ui.pending_leave.take();
            }
        });
        false
    }
    pub(super) fn smoke_has_prompt(ui: &Rc<Ui>) -> bool {
        ui.settings_prompt.borrow().is_some()
    }
    pub(super) fn discard_preview(&self) {
        self.is_dirty.set(false);
        self.dirty.set_visible(false);
        self.save.set_sensitive(false);
    }

    pub(super) fn saved_settings(&self) -> model::Settings {
        self.baseline.borrow().0.clone()
    }
}

impl Ui {
    pub(super) fn settings(self: &Rc<Self>, heading: &gtk::Box) {
        self.body.add_css_class("settings-page");
        let settings = self.service.snapshot().settings;
        let save = primary("保存", "object-select-symbolic");
        save.set_widget_name("settings-save");
        let dirty = label("未保存", "settings-dirty-label");
        dirty.set_widget_name("settings-unsaved");
        dirty.set_valign(gtk::Align::Center);
        heading.append(&dirty);
        heading.append(&save);
        let stack = gtk::Stack::builder()
            .hhomogeneous(false)
            .vhomogeneous(false)
            .build();
        stack.set_widget_name("settings-sections");
        let tabs = gtk::StackSwitcher::builder()
            .stack(&stack)
            .halign(gtk::Align::Start)
            .build();
        tabs.add_css_class("editor-tabs");
        self.body.append(&tabs);
        self.body.append(&stack);
        let general_page = gtk::Box::new(gtk::Orientation::Vertical, 24);
        let network_page = gtk::Box::new(gtk::Orientation::Vertical, 24);
        let tun_page = gtk::Box::new(gtk::Orientation::Vertical, 24);
        let core_page = gtk::Box::new(gtk::Orientation::Vertical, 24);
        stack.add_titled(&general_page, Some("general"), "常规");
        stack.add_titled(&network_page, Some("network"), "网络");
        stack.add_titled(&tun_page, Some("tun"), "虚拟网卡");
        stack.add_titled(&core_page, Some("core"), "内核");
        let appearance = group("外观与启动");
        let theme = combo(
            "外观",
            &["跟随系统", "浅色", "深色"],
            match settings.theme.as_str() {
                "light" => 1,
                "dark" => 2,
                _ => 0,
            },
        );
        appearance.add(&theme);
        // Discrete sizes keep the preview predictable: each step is a whole
        // point, matching how FlClash offers a short list instead of a slider.
        let sizes: Vec<String> = (model::FONT_SIZE_MIN..=model::FONT_SIZE_MAX)
            .map(|size| format!("{size} pt"))
            .collect();
        let font_size = adw::ComboRow::builder()
            .title("字体大小")
            .model(&gtk::StringList::new(
                &sizes.iter().map(String::as_str).collect::<Vec<_>>(),
            ))
            .selected(
                settings
                    .font_size
                    .clamp(model::FONT_SIZE_MIN, model::FONT_SIZE_MAX)
                    - model::FONT_SIZE_MIN,
            )
            .build();
        appearance.add(&font_size);
        let crisp_text = switch_row("清晰文字", "", settings.crisp_text);
        crisp_text.set_tooltip_text(Some("将字形对齐到像素；关闭后跟随系统文字渲染"));
        appearance.add(&crisp_text);
        let weak = Rc::downgrade(self);
        let crisp = crisp_text.downgrade();
        font_size.connect_selected_notify(move |row| {
            if let (Some(ui), Some(crisp)) = (weak.upgrade(), crisp.upgrade()) {
                ui.apply_font_size(model::FONT_SIZE_MIN + row.selected(), crisp.is_active());
            }
        });
        let weak = Rc::downgrade(self);
        let size = font_size.downgrade();
        crisp_text.connect_active_notify(move |row| {
            if let (Some(ui), Some(size)) = (weak.upgrade(), size.upgrade()) {
                ui.apply_font_size(model::FONT_SIZE_MIN + size.selected(), row.is_active());
            }
        });
        theme.connect_selected_notify(|row| {
            apply_theme(match row.selected() {
                1 => "light",
                2 => "dark",
                _ => "system",
            })
        });
        let autostart = switch_row("登录时启动", "", platform::autostart_enabled());
        appearance.add(&autostart);
        let auto_core = switch_row("启动时连接", "", settings.auto_start);
        appearance.add(&auto_core);
        let restart = switch_row("内核异常重启", "", settings.auto_restart);
        appearance.add(&restart);
        let update_subs = switch_row("启动时更新订阅", "", settings.update_subscriptions_on_start);
        appearance.add(&update_subs);
        let detect_ip = switch_row("自动检测出口 IP", "", settings.auto_detect_ip);
        appearance.add(&detect_ip);
        let acceleration = switch_row("硬件加速", "重启应用后生效", settings.hardware_acceleration);
        acceleration.set_tooltip_text(Some("开启后使用系统图形加速，可能增加内存占用"));
        appearance.add(&acceleration);
        general_page.append(&appearance);

        let network = group("代理");
        let proxy = switch_row("连接时启用系统代理", "", settings.system_proxy);
        network.add(&proxy);
        let ipv6 = switch_row("IPv6", "", settings.ipv6);
        network.add(&ipv6);
        let lan = switch_row("允许局域网访问", "", settings.allow_lan);
        lan.set_tooltip_text(Some("允许同一网络的设备使用本地代理端口"));
        network.add(&lan);
        let mixed_port = adw::SpinRow::with_range(1.0, 65535.0, 1.0);
        mixed_port.set_title("代理端口");
        mixed_port.set_value(settings.mixed_port as f64);
        network.add(&mixed_port);
        let api_port = adw::SpinRow::with_range(1.0, 65535.0, 1.0);
        api_port.set_title("控制端口");
        api_port.set_value(settings.api_port as f64);
        network.add(&api_port);
        network_page.append(&network);
        let routing = group("分流");
        let bypass = switch_row("绕过局域网", "", settings.bypass_lan);
        routing.add(&bypass);
        let sniff = switch_row("流量嗅探", "", settings.sniff);
        routing.add(&sniff);
        let dns = group("DNS");
        let hijack = switch_row("DNS 劫持", "", settings.dns_hijack);
        dns.add(&hijack);
        let cache = switch_row("DNS 缓存", "", settings.dns_cache);
        dns.add(&cache);
        network_page.append(&routing);
        network_page.append(&dns);

        let tun_group = group("虚拟网卡");
        let tun = switch_row("启用 TUN", "", settings.tun_enabled);
        tun_group.add(&tun);
        let stack = combo(
            "协议栈",
            &["System", "gVisor", "Mixed"],
            match settings.tun_stack.as_str() {
                "gvisor" => 1,
                "mixed" => 2,
                _ => 0,
            },
        );
        tun_group.add(&stack);
        let mtu = adw::SpinRow::with_range(576.0, 9000.0, 1.0);
        mtu.set_title("MTU");
        mtu.set_value(settings.tun_mtu as f64);
        tun_group.add(&mtu);
        let strict = switch_row("严格路由", "", settings.strict_route);
        tun_group.add(&strict);
        for widget in [
            stack.clone().upcast::<gtk::Widget>(),
            mtu.clone().upcast(),
            strict.clone().upcast(),
        ] {
            widget.set_sensitive(settings.tun_enabled);
            tun.connect_active_notify(move |row| widget.set_sensitive(row.is_active()));
        }
        let permissions = adw::ActionRow::builder().title("网络权限").build();
        let authorize = gtk::Button::with_label("授权");
        authorize.set_valign(gtk::Align::Center);
        authorize.set_tooltip_text(Some("为 sing-box 内核授予创建虚拟网卡所需的权限"));
        permissions.add_suffix(&authorize);
        let weak = Rc::downgrade(self);
        authorize.connect_clicked(move |button| {
            if let Some(ui) = weak.upgrade() {
                button.set_sensitive(false);
                let button = button.downgrade();
                ui.task(
                    "授权",
                    |s| Ok(s.authorize_tun()),
                    move |ui, result| {
                        if let Some(button) = button.upgrade() {
                            button.set_sensitive(true);
                        }
                        match result {
                            Ok(()) => ui.notify("已授权"),
                            Err(e) => ui.error("授权失败", format!("{e:#}")),
                        }
                    },
                );
            }
        });
        tun_group.add(&permissions);
        tun_page.append(&tun_group);

        self.core_panel(&core_page);
        let core = group("内核设置");
        let core_path = LabeledEntry::new("内核路径（留空自动检测）", &settings.core_path);
        let browse = icon_button("folder-open-symbolic", "选择 sing-box 内核");
        core_path.with_suffix(&browse);
        let parent = self.window.clone();
        let path_entry = core_path.entry.clone();
        browse.connect_clicked(move |_| {
            let entry = path_entry.clone();
            gtk::FileDialog::builder().title("选择内核").build().open(
                Some(&parent),
                None::<&gio::Cancellable>,
                move |result| {
                    if let Ok(file) = result
                        && let Some(path) = file.path()
                    {
                        entry.set_text(&path.to_string_lossy());
                    }
                },
            );
        });
        core.add(&core_path.root);
        let levels = ["trace", "debug", "info", "warn", "error", "fatal", "panic"];
        let log = combo(
            "日志级别",
            &levels,
            levels
                .iter()
                .position(|l| *l == settings.log_level)
                .unwrap_or(4) as u32,
        );
        core.add(&log);
        core_page.append(&core);

        let testing = group("测速");
        let test_url = LabeledEntry::new("测试地址", &settings.test_url);
        testing.add(&test_url.root);
        let timeout = adw::SpinRow::with_range(500.0, 30000.0, 500.0);
        timeout.set_title("超时（毫秒）");
        timeout.set_value(settings.test_timeout as f64);
        testing.add(&timeout);
        network_page.append(&testing);
        let data = group("应用");
        let dir = adw::ActionRow::builder()
            .title("配置目录")
            .subtitle(self.service.dir().to_string_lossy().as_ref())
            .build();
        let open = icon_button("folder-open-symbolic", "打开配置目录");
        dir.add_suffix(&open);
        let weak = Rc::downgrade(self);
        open.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                let file = gio::File::for_path(ui.service.dir());
                let weak = Rc::downgrade(&ui);
                gtk::FileLauncher::new(Some(&file)).launch(
                    Some(&ui.window),
                    None::<&gio::Cancellable>,
                    move |result| {
                        if let (Err(e), Some(ui)) = (result, weak.upgrade()) {
                            ui.error("打开失败", e);
                        }
                    },
                );
            }
        });
        data.add(&dir);
        data.add(
            &adw::ActionRow::builder()
                .title("AeroBox 版本")
                .subtitle(option_env!("AEROBOX_VERSION").unwrap_or(env!("CARGO_PKG_VERSION")))
                .build(),
        );
        general_page.append(&data);
        let weak = Rc::downgrade(self);
        let saved = self.service.snapshot().settings;
        let read = Rc::new(move || {
            let next = model::Settings {
                font_size: model::FONT_SIZE_MIN + font_size.selected(),
                crisp_text: crisp_text.is_active(),
                theme: match theme.selected() {
                    1 => "light",
                    2 => "dark",
                    _ => "system",
                }
                .into(),
                core_path: core_path.text().trim().into(),
                auto_start: auto_core.is_active(),
                auto_restart: restart.is_active(),
                system_proxy: proxy.is_active(),
                ipv6: ipv6.is_active(),
                allow_lan: lan.is_active(),
                mixed_port: mixed_port.value() as u16,
                api_port: api_port.value() as u16,
                bypass_lan: bypass.is_active(),
                sniff: sniff.is_active(),
                dns_hijack: hijack.is_active(),
                dns_cache: cache.is_active(),
                auto_detect_ip: detect_ip.is_active(),
                hardware_acceleration: acceleration.is_active(),
                update_subscriptions_on_start: update_subs.is_active(),
                tun_enabled: tun.is_active(),
                tun_stack: match stack.selected() {
                    1 => "gvisor",
                    2 => "mixed",
                    _ => "system",
                }
                .into(),
                tun_mtu: mtu.value() as u32,
                strict_route: strict.is_active(),
                log_level: levels[log.selected() as usize].into(),
                test_url: test_url.text().trim().into(),
                test_timeout: timeout.value() as u32,
                ..saved.clone()
            };
            (next, autostart.is_active())
        });
        let baseline = RefCell::new({
            let mut current = read();
            current.0 = self.service.snapshot().settings;
            current
        });
        let panel = Rc::new(SettingsPanel {
            save: save.clone(),
            stack: self
                .body
                .last_child()
                .and_then(|widget| widget.downcast::<gtk::Stack>().ok())
                .expect("settings form stack"),
            tabs: self
                .body
                .first_child()
                .and_then(|widget| widget.next_sibling())
                .and_then(|widget| widget.downcast::<gtk::StackSwitcher>().ok())
                .expect("settings tabs"),
            dirty,
            read: read.clone(),
            baseline,
            is_dirty: Cell::new(false),
            saving: Cell::new(false),
        });
        let update_dirty = {
            let panel = panel.clone();
            Rc::new(move || panel.update_dirty())
        };
        for row in descendants(&self.body)
            .iter()
            .filter_map(|widget| widget.clone().downcast::<adw::SwitchRow>().ok())
        {
            let update = update_dirty.clone();
            row.connect_active_notify(move |_| update());
        }
        for row in descendants(&self.body)
            .iter()
            .filter_map(|widget| widget.clone().downcast::<adw::ComboRow>().ok())
        {
            let update = update_dirty.clone();
            row.connect_selected_notify(move |_| update());
        }
        for row in descendants(&self.body)
            .iter()
            .filter_map(|widget| widget.clone().downcast::<adw::SpinRow>().ok())
        {
            let update = update_dirty.clone();
            row.connect_value_notify(move |_| update());
        }
        for row in descendants(&self.body)
            .iter()
            .filter_map(|widget| widget.clone().downcast::<gtk::Entry>().ok())
        {
            let update = update_dirty.clone();
            row.connect_changed(move |_| update());
        }
        panel.update_dirty();
        self.settings_panel.replace(Some(panel.clone()));
        save.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                panel.save(&ui);
            }
        });
    }
}

fn descendants(root: &impl IsA<gtk::Widget>) -> Vec<gtk::Widget> {
    let mut widgets = vec![];
    let mut child = root.first_child();
    while let Some(widget) = child {
        child = widget.next_sibling();
        widgets.extend(descendants(&widget));
        widgets.push(widget);
    }
    widgets
}
fn group(title: &str) -> adw::PreferencesGroup {
    let group = adw::PreferencesGroup::new();
    group.set_title(title);
    group
}
fn combo(title: &str, choices: &[&str], selected: u32) -> adw::ComboRow {
    adw::ComboRow::builder()
        .title(title)
        .model(&gtk::StringList::new(choices))
        .selected(selected)
        .build()
}

/// Height of the first settings row, used to prove that a font change moves
/// layout and not just glyph size.
pub(super) fn smoke_unsaved(ui: &Rc<Ui>, response: Option<&str>) -> Result<()> {
    if let Some(response) = response {
        let prompt = ui
            .settings_prompt
            .borrow()
            .as_ref()
            .cloned()
            .context("离开未保存设置时没有确认提示")?;
        anyhow::ensure!(ui.page.get() == Page::Settings, "确认前已离开设置页");
        prompt.emit_by_name::<()>("response", &[&response]);
        return Ok(());
    }
    smoke_edit(ui)?;
    let weak = Rc::downgrade(ui);
    ui.confirm_discard_settings(move || {
        if let Some(ui) = weak.upgrade() {
            ui.navigate(Page::Nodes);
        }
    });
    anyhow::ensure!(ui.page.get() == Page::Settings, "确认前已经切换页面");
    Ok(())
}

pub(super) fn smoke_edit(ui: &Rc<Ui>) -> Result<()> {
    use anyhow::ensure;
    let panel = ui
        .settings_panel
        .borrow()
        .as_ref()
        .cloned()
        .context("缺少设置页控制器")?;
    let (saved, _) = panel.baseline.borrow().clone();
    ensure!(
        saved == ui.service.snapshot().settings,
        "设置基线与持久化值不一致"
    );
    let widgets = descendants(&ui.body);
    let mtu = widgets
        .iter()
        .filter_map(|widget| widget.clone().downcast::<adw::SpinRow>().ok())
        .find(|row| row.title() == "MTU")
        .context("缺少 MTU 控件")?;
    mtu.set_value(saved.tun_mtu as f64 + 100.0);
    ensure!(panel.is_dirty.get(), "修改后没有未保存标记");
    ensure!(panel.save.is_sensitive(), "修改后保存按钮没有启用");
    mtu.set_value(saved.tun_mtu as f64);
    ensure!(
        !panel.is_dirty.get(),
        "改回原值仍显示未保存: current={:?}, saved={:?}",
        (panel.read)(),
        panel.baseline.borrow()
    );
    ensure!(!panel.save.is_sensitive(), "改回原值仍可以保存");
    mtu.set_value(saved.tun_mtu as f64 + 100.0);
    let theme = widgets
        .iter()
        .filter_map(|widget| widget.clone().downcast::<adw::ComboRow>().ok())
        .find(|row| row.title() == "外观")
        .context("缺少外观控件")?;
    theme.set_selected(2);
    let font_size = widgets
        .iter()
        .filter_map(|widget| widget.clone().downcast::<adw::ComboRow>().ok())
        .find(|row| row.title() == "字体大小")
        .context("缺少字体大小控件")?;
    font_size.set_selected(if saved.font_size == model::FONT_SIZE_MIN {
        model::FONT_SIZE_MAX - model::FONT_SIZE_MIN
    } else {
        0
    });
    ensure!(
        ui.service.snapshot().settings.font_size == saved.font_size,
        "预览提前写入设置"
    );
    Ok(())
}

pub(super) fn smoke_restored(ui: &Rc<Ui>) -> Result<()> {
    let saved = ui.service.snapshot().settings;
    anyhow::ensure!(
        ui.typography.preview() == (saved.font_size, saved.crisp_text),
        "放弃更改没有恢复字体预览"
    );
    let widgets = descendants(&ui.body);
    for (title, selected) in [
        ("字体大小", saved.font_size - model::FONT_SIZE_MIN),
        ("外观", 1),
    ] {
        let actual = widgets
            .iter()
            .filter_map(|widget| widget.clone().downcast::<adw::ComboRow>().ok())
            .find(|row| row.title() == title)
            .with_context(|| format!("缺少{title}控件"))?
            .selected();
        anyhow::ensure!(actual == selected, "放弃更改没有恢复{title}预览");
    }
    Ok(())
}

pub(super) fn smoke_row_height(ui: &Rc<Ui>) -> Option<i32> {
    fn tallest(widget: &gtk::Widget) -> Option<adw::ActionRow> {
        if let Some(row) = widget.downcast_ref::<adw::ActionRow>() {
            return Some(row.clone());
        }
        let mut child = widget.first_child();
        while let Some(widget) = child {
            child = widget.next_sibling();
            if let Some(found) = tallest(&widget) {
                return Some(found);
            }
        }
        None
    }
    let row = tallest(ui.body.upcast_ref())?;
    // Measure rather than read `height()`: allocation happens on the next
    // frame, so the cached height still belongs to the previous font size.
    let (_, natural, _, _) = row.measure(gtk::Orientation::Vertical, -1);
    Some(natural)
}

pub(super) fn smoke_settings(ui: &Rc<Ui>, verify: bool) -> Result<()> {
    use anyhow::ensure;
    let widgets = descendants(&ui.body);
    let saves: Vec<_> = widgets
        .iter()
        .filter_map(|w| w.clone().downcast::<gtk::Button>().ok())
        .filter(|b| b.widget_name() == "settings-save")
        .collect();
    ensure!(saves.len() == 1, "设置必须只有一个保存按钮");
    let save = &saves[0];
    if verify {
        let settings = ui.service.snapshot().settings;
        ensure!(ui.jobs.get() == 0, "设置保存尚未完成");
        ensure!(
            !settings.ipv6
                && settings.font_size == model::FONT_SIZE_MAX
                && settings.crisp_text
                && settings.allow_lan
                && !settings.dns_cache
                && settings.tun_enabled
                && settings.hardware_acceleration
                && settings.tun_stack == "gvisor"
                && settings.tun_mtu == 1400,
            "设置控件没有持久化"
        );
        ensure!(!ui.service.status().running, "设置测试意外启动了内核");
        ensure!(
            !save.is_sensitive()
                && descendants(&ui.body)
                    .iter()
                    .filter_map(|widget| widget.downcast_ref::<gtk::Label>())
                    .all(|label| label.widget_name() != "settings-unsaved" || !label.is_visible()),
            "保存完成后仍显示未保存状态"
        );
        ensure!(
            !descendants(save).iter().any(|w| w.is::<gtk::Spinner>()),
            "保存完成后仍有进度指示器"
        );
        return Ok(());
    }
    for (title, value) in [
        ("IPv6", false),
        ("允许局域网访问", true),
        ("DNS 缓存", false),
        ("启用 TUN", true),
        ("硬件加速", true),
    ] {
        let row = widgets
            .iter()
            .filter_map(|w| w.clone().downcast::<adw::SwitchRow>().ok())
            .find(|row| row.title() == title)
            .with_context(|| format!("缺少开关 {title}"))?;
        row.set_active(value);
    }
    let stack = widgets
        .iter()
        .filter_map(|w| w.clone().downcast::<adw::ComboRow>().ok())
        .find(|row| row.title() == "协议栈")
        .context("缺少 TUN 协议栈")?;
    ensure!(stack.is_sensitive(), "启用 TUN 后无法选择协议栈");
    stack.set_selected(1);
    widgets
        .iter()
        .filter_map(|w| w.clone().downcast::<adw::SpinRow>().ok())
        .find(|row| row.title() == "MTU")
        .context("缺少 MTU 控件")?
        .set_value(1400.0);
    widgets
        .iter()
        .filter_map(|w| w.clone().downcast::<adw::ComboRow>().ok())
        .find(|row| row.title() == "字体大小")
        .context("缺少字体大小控件")?
        .set_selected(model::FONT_SIZE_MAX - model::FONT_SIZE_MIN);
    save.emit_clicked();
    ensure!(!save.is_sensitive(), "保存期间没有禁用按钮");
    ensure!(
        descendants(save)
            .iter()
            .filter_map(|w| w.clone().downcast::<gtk::Spinner>().ok())
            .any(|spinner| spinner.is_spinning()),
        "进度指示器不在保存按钮中"
    );
    widgets
        .iter()
        .filter_map(|w| w.clone().downcast::<gtk::Stack>().ok())
        .find(|stack| stack.widget_name() == "settings-sections")
        .context("缺少设置分组")?
        .set_visible_child_name("tun");
    let scroll = ui
        .body
        .ancestor(gtk::ScrolledWindow::static_type())
        .and_then(|w| w.downcast::<gtk::ScrolledWindow>().ok())
        .context("缺少设置滚动区域")?;
    scroll.vadjustment().set_value(1000.0);
    Ok(())
}
