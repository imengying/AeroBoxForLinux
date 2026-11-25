use super::*;

type SettingsAction = Rc<dyn Fn(&Rc<Ui>, bool)>;

pub(super) struct SettingsPanel {
    save: gtk::Button,
    form: gtk::Box,
    autostart: adw::SwitchRow,
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
        let (current, login) = (self.read)();
        let saved = ui.service.snapshot().settings;
        let previous = self.baseline.borrow().0.clone();
        let next = model::Settings {
            active_subscription: saved.active_subscription,
            routing_mode: saved.routing_mode,
            tun_enabled: saved.tun_enabled,
            ..current
        };
        if let Err(error) = next.validate() {
            ui.pending_leave.replace(after);
            ui.error("设置无效", error);
            return;
        }
        self.begin_save();
        let weak = Rc::downgrade(self);
        ui.button_task(
            &self.save,
            "保存中…",
            move |service| service.save_form(previous.clone(), next, login),
            move |ui, result| {
                let Some(panel) = weak.upgrade() else {
                    ui.pending_leave.replace(after);
                    return;
                };
                panel.saving.set(false);
                panel.form.set_sensitive(true);
                match result {
                    Ok(()) => {
                        panel.is_dirty.set(false);
                        panel.save.set_visible(false);
                        panel.save.set_sensitive(false);
                        panel
                            .baseline
                            .replace((ui.service.snapshot().settings, login));
                        ui.notify("设置已保存");
                        if let Some(after) = after {
                            after();
                        }
                    }
                    Err(error) => {
                        panel.is_dirty.set(true);
                        panel.save.set_visible(true);
                        panel.save.set_sensitive(true);
                        ui.pending_leave.replace(after);
                        panel.autostart.set_active(ui.service.autostart_enabled());
                        ui.error("保存失败", format!("{error:#}"));
                    }
                }
            },
        );
    }

    fn update_dirty(&self) {
        let (current, login) = (self.read)();
        let baseline = self.baseline.borrow();
        let dirty = !current.same_preferences(&baseline.0) || login != baseline.1;
        self.is_dirty.set(dirty);
        if !self.saving.get() {
            self.save.set_visible(dirty);
            self.save.set_sensitive(dirty);
        }
    }

    pub(super) fn confirm_leave(self: &Rc<Self>, ui: &Rc<Ui>, leave: Rc<dyn Fn()>) -> bool {
        if self.saving.get() || ui.settings_prompt.borrow().is_some() {
            return false;
        }
        if !self.is_dirty.get() {
            return true;
        }
        ui.pending_leave.replace(Some(leave));
        let dialog = alert_dialog(
            "保存设置更改？",
            "当前设置尚未保存。保存后离开，或放弃本次修改。",
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
        dialog.connect_response(None, move |dialog, response| {
            let (Some(panel), Some(ui)) = (weak.upgrade(), weak_ui.upgrade()) else {
                return;
            };
            if !ui.finish_settings_prompt(dialog) {
                return;
            }
            let after = ui.pending_leave.take();
            match response {
                "discard" => {
                    let settings = panel.saved_settings();
                    ui.apply_font_size(settings.font_size);
                    apply_theme(&settings.theme);
                    panel.is_dirty.set(false);
                    if let Some(after) = after {
                        after();
                    }
                }
                "save" => {
                    ui.pending_leave.replace(after);
                    panel.save(&ui);
                }
                _ => {
                    ui.pending_leave.take();
                }
            }
        });
        ui.settings_prompt.replace(Some(dialog.clone()));
        dialog.present(Some(&ui.window));
        false
    }
    #[cfg(feature = "ui-smoke")]
    pub(super) fn smoke_has_prompt(ui: &Rc<Ui>) -> bool {
        ui.settings_prompt.borrow().is_some()
    }
    pub(super) fn discard_preview(&self) {
        self.is_dirty.set(false);
        self.save.set_visible(false);
        self.save.set_sensitive(false);
    }

    pub(super) fn saved_settings(&self) -> model::Settings {
        self.baseline.borrow().0.clone()
    }

    fn sync_autostart(&self, service: &Service) {
        self.autostart.set_active(service.autostart_enabled());
        self.update_dirty();
    }

    fn busy(&self, active: bool) {
        self.saving.set(active);
        self.form.set_sensitive(!active);
        self.save.set_visible(!active && self.is_dirty.get());
        self.save.set_sensitive(!active && self.is_dirty.get());
    }

    fn begin_save(&self) {
        self.busy(true);
        self.save.set_visible(true);
    }

    fn request_save(ui: &Rc<Ui>, action: &str, on_ready: SettingsAction) {
        let panel = ui
            .settings_panel
            .borrow()
            .as_ref()
            .cloned()
            .expect("settings controller");
        if panel.saving.get() || ui.settings_prompt.borrow().is_some() {
            return;
        }
        let login = panel.baseline.borrow().1;
        if !panel.is_dirty.get() {
            on_ready(ui, login);
            return;
        }
        let prompt = alert_dialog(
            "有未保存的更改",
            &format!("保存当前设置后{action}，或放弃未保存的修改。"),
        );
        prompt.add_response("cancel", "取消");
        prompt.add_response("discard", "放弃并继续");
        prompt.add_response("save", "保存并继续");
        prompt.set_response_appearance("discard", adw::ResponseAppearance::Destructive);
        prompt.set_response_appearance("save", adw::ResponseAppearance::Suggested);
        prompt.set_default_response(Some("save"));
        prompt.set_close_response("cancel");
        let weak_ui = Rc::downgrade(ui);
        let weak_panel = Rc::downgrade(&panel);
        prompt.connect_response(None, move |prompt, response| {
            let (Some(ui), Some(panel)) = (weak_ui.upgrade(), weak_panel.upgrade()) else {
                return;
            };
            if !ui.finish_settings_prompt(prompt) {
                return;
            }
            match response {
                "discard" => {
                    let saved = panel.saved_settings();
                    let login = panel.baseline.borrow().1;
                    ui.apply_font_size(saved.font_size);
                    apply_theme(&saved.theme);
                    ui.refresh(Page::Settings);
                    on_ready(&ui, login);
                }
                "save" => {
                    let weak_ui = Rc::downgrade(&ui);
                    let on_ready = on_ready.clone();
                    ui.pending_leave.replace(Some(Rc::new(move || {
                        if let Some(ui) = weak_ui.upgrade() {
                            on_ready(&ui, ui.service.autostart_enabled());
                        }
                    })));
                    panel.save(&ui);
                }
                _ => {}
            }
        });
        ui.settings_prompt.replace(Some(prompt.clone()));
        prompt.present(Some(&ui.window));
    }
}

impl Ui {
    fn diagnostics_row(self: &Rc<Self>, group: &adw::PreferencesGroup) {
        let row = adw::ActionRow::builder().title("连接诊断").build();
        let button = gtk::Button::with_label("检测");
        button.add_css_class("secondary-action");
        button.set_valign(gtk::Align::Center);
        button.set_widget_name("connection-diagnostics");
        row.add_suffix(&button);
        row.set_activatable_widget(Some(&button));
        group.add(&row);
        let weak = Rc::downgrade(self);
        button.connect_clicked(move |button| {
            if let Some(ui) = weak.upgrade() {
                ui.button_task(
                    button,
                    "检测中…",
                    |service| service.diagnose_connection(),
                    |ui, result| {
                        let report = match result {
                            Ok(report) => report,
                            Err(error) => format!("{error:#}"),
                        };
                        let text = format!(
                            "AeroBox {}\n\n{report}",
                            option_env!("AEROBOX_VERSION").unwrap_or(env!("CARGO_PKG_VERSION")),
                        );
                        let dialog = alert_dialog("连接诊断", &text);
                        dialog.add_response("copy", "复制结果");
                        dialog.add_response("close", "关闭");
                        dialog.set_default_response(Some("close"));
                        dialog.set_close_response("close");
                        let clipboard = ui.window.clipboard();
                        dialog.connect_response(Some("copy"), move |_, _| {
                            clipboard.set_text(&text);
                        });
                        dialog.present(Some(&ui.window));
                    },
                );
            }
        });
    }

    pub(super) fn settings(self: &Rc<Self>, _heading: &gtk::Box) {
        self.body.add_css_class("settings-page");
        let settings = self.service.snapshot().settings;
        let save = primary("保存", "object-select-symbolic");
        save.set_widget_name("settings-save");
        save.add_css_class("floating-save");
        save.set_halign(gtk::Align::End);
        save.set_valign(gtk::Align::End);
        save.set_margin_end(4);
        save.set_margin_bottom(4);
        save.set_visible(false);
        save.set_sensitive(false);
        self.floating.add_overlay(&save);
        self.settings_action.replace(Some(save.clone()));
        let form = gtk::Box::new(gtk::Orientation::Vertical, 24);
        form.set_widget_name("settings-form");
        self.body.append(&form);
        self.body.set_margin_bottom(84);
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
        let weak = Rc::downgrade(self);
        font_size.connect_selected_notify(move |row| {
            if let Some(ui) = weak.upgrade() {
                ui.apply_font_size(model::FONT_SIZE_MIN + row.selected());
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
        let detect_ip = switch_row("自动检测出口 IP", "", settings.auto_detect_ip);
        appearance.add(&detect_ip);
        form.append(&appearance);

        let network = group("代理");
        let proxy = switch_row("连接时启用系统代理", "", settings.system_proxy);
        network.add(&proxy);
        let ipv6 = switch_row("IPv6", "", settings.ipv6);
        network.add(&ipv6);
        form.append(&network);
        let routing = group("分流");
        let bypass = switch_row("绕过局域网", "", settings.bypass_lan);
        routing.add(&bypass);
        let sniff = switch_row("流量嗅探", "", settings.sniff);
        routing.add(&sniff);
        let dns = group("DNS");
        dns.set_description(Some(
            "支持 udp://、tcp://、tls://、https:// 和 quic://；远程 DNS 经所选节点查询。",
        ));
        let direct_dns = LabeledEntry::new("直连 DNS", &settings.direct_dns);
        direct_dns.root.set_tooltip_text(Some(
            "例如 udp://223.5.5.5 或 https://dns.alidns.com/dns-query",
        ));
        dns.add(&direct_dns.root);
        let remote_dns = LabeledEntry::new("远程 DNS", &settings.remote_dns);
        remote_dns
            .root
            .set_tooltip_text(Some("远程 DNS 经代理查询；域名型服务器使用直连 DNS 解析"));
        dns.add(&remote_dns.root);
        let hijack = switch_row("DNS 劫持", "拦截局域网 DNS 查询", settings.dns_hijack);
        dns.add(&hijack);
        let cache = switch_row("DNS 缓存", "缓存域名解析结果", settings.dns_cache);
        dns.add(&cache);
        form.append(&routing);
        form.append(&dns);

        let tun_group = group("虚拟网卡");
        let mtu = number_entry("MTU", &settings.tun_mtu.to_string());
        tun_group.add(&mtu.root);
        form.append(&tun_group);

        let logging = group("日志与诊断");
        let levels = ["trace", "debug", "info", "warn", "error"];
        let log = combo(
            "日志级别",
            &levels,
            levels
                .iter()
                .position(|l| *l == settings.log_level)
                .unwrap_or(4) as u32,
        );
        logging.add(&log);
        self.diagnostics_row(&logging);
        form.append(&logging);

        let testing = group("测速");
        let test_url = LabeledEntry::new("测试地址", &settings.test_url);
        testing.add(&test_url.root);
        let timeout = number_entry("超时（毫秒）", &settings.test_timeout.to_string());
        testing.add(&timeout.root);
        form.append(&testing);
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
        form.append(&data);
        let weak = Rc::downgrade(self);
        let reset = adw::ActionRow::builder()
            .title("恢复默认设置")
            .subtitle("保留订阅、节点和规则，仅重置设置")
            .build();
        let reset_button = gtk::Button::with_label("恢复默认");
        reset_button.add_css_class("compact-action");
        reset_button.set_valign(gtk::Align::Center);
        reset.add_suffix(&reset_button);
        data.add(&reset);
        reset_button.connect_clicked(move |_| {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            if ui.settings_panel.borrow().is_none() {
                return;
            }
            let ready = Rc::new(move |ui: &Rc<Ui>, login: bool| {
                let dialog = alert_dialog("恢复默认设置？", "恢复默认设置，保留订阅、节点和规则。");
                dialog.add_response("cancel", "取消");
                dialog.add_response("reset", "恢复默认");
                dialog.set_response_appearance("reset", adw::ResponseAppearance::Destructive);
                dialog.set_close_response("cancel");
                let weak = Rc::downgrade(ui);
                dialog.connect_response(None, move |dialog, response| {
                    let Some(ui) = weak.upgrade() else {
                        return;
                    };
                    if !ui.finish_settings_prompt(dialog) || response != "reset" {
                        return;
                    }
                    let saved = ui.service.snapshot().settings;
                    let settings = model::Settings {
                        active_subscription: saved.active_subscription,
                        routing_mode: saved.routing_mode,
                        width: saved.width,
                        height: saved.height,
                        ..model::Settings::default()
                    };
                    let Some(panel) = ui.settings_panel.borrow().as_ref().cloned() else {
                        return;
                    };
                    let previous = panel.saved_settings();
                    ui.apply_font_size(settings.font_size);
                    apply_theme(&settings.theme);
                    panel.begin_save();
                    ui.button_task(
                        &panel.save,
                        "恢复中…",
                        move |service| service.reset_form(previous, login),
                        |ui, result| match result {
                            Ok(()) => {
                                ui.notify("已恢复默认设置");
                                ui.refresh(Page::Settings);
                            }
                            Err(error) => {
                                let saved = ui.service.snapshot().settings;
                                ui.apply_font_size(saved.font_size);
                                apply_theme(&saved.theme);
                                ui.error("恢复默认失败", format!("{error:#}"));
                                if let Some(panel) = ui.settings_panel.borrow().as_ref() {
                                    panel.busy(false);
                                    panel.update_dirty();
                                }
                            }
                        },
                    );
                });
                ui.settings_prompt.replace(Some(dialog.clone()));
                dialog.present(Some(&ui.window));
            });
            SettingsPanel::request_save(&ui, "恢复默认设置", ready);
        });
        let backup_group = group("数据管理");
        backup_group.set_description(Some(
            "备份包含订阅、节点、规则和设置；恢复保留现有资源并添加备份副本。",
        ));
        let export_row = adw::ActionRow::builder()
            .title("导出备份")
            .subtitle("包含明文节点凭据，请妥善保管备份文件")
            .build();
        let export = gtk::Button::with_label("导出");
        export.add_css_class("compact-action");
        export.set_valign(gtk::Align::Center);
        export_row.add_suffix(&export);
        backup_group.add(&export_row);
        let import_row = adw::ActionRow::builder()
            .title("合并恢复备份")
            .subtitle("添加订阅和规则副本，并按备份恢复设置")
            .build();
        let restore = gtk::Button::with_label("选择文件");
        restore.add_css_class("compact-action");
        restore.set_valign(gtk::Align::Center);
        import_row.add_suffix(&restore);
        backup_group.add(&import_row);
        form.append(&backup_group);
        let weak = Rc::downgrade(self);
        export.connect_clicked(move |button| {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            let button = button.clone();
            let ready = Rc::new(move |ui: &Rc<Ui>, _: bool| {
                let button = button.clone();
                let finish = Rc::new(|ui: &Rc<Ui>, result: Result<()>| {
                    if let Some(panel) = ui.settings_panel.borrow().as_ref() {
                        panel.busy(false);
                        panel.update_dirty();
                    }
                    match result {
                        Ok(()) => ui.notify("备份已导出"),
                        Err(error) => ui.error("导出备份失败", format!("{error:#}")),
                    }
                });
                // Weston has no desktop file portal. The explicit smoke-test
                // directory exercises the real export without needing one.
                #[cfg(feature = "ui-smoke")]
                if let Some(dir) = ui.smoke_dir.borrow().clone() {
                    let path = dir.join("smoke-backup.json");
                    ui.button_task(
                        &button,
                        "导出中…",
                        move |service| service.export_backup(&path),
                        move |ui, result| finish(ui, result),
                    );
                    return;
                }
                let dialog = gtk::FileDialog::builder()
                    .title("导出 AeroBox 备份")
                    .initial_name("AeroBox-backup.json")
                    .build();
                let weak = Rc::downgrade(ui);
                let finish = finish.clone();
                dialog.save(Some(&ui.window), None::<&gio::Cancellable>, move |result| {
                    let (Ok(file), Some(ui)) = (result, weak.upgrade()) else {
                        return;
                    };
                    let Some(path) = file.path() else {
                        return;
                    };
                    if let Some(panel) = ui.settings_panel.borrow().as_ref() {
                        panel.busy(true);
                    }
                    ui.button_task(
                        &button,
                        "导出中…",
                        move |service| service.export_backup(&path),
                        move |ui, result| finish(ui, result),
                    );
                });
            });
            SettingsPanel::request_save(&ui, "导出备份", ready);
        });
        let weak = Rc::downgrade(self);
        restore.connect_clicked(move |button| {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            let button = button.clone();
            let restore_file = Rc::new(move |ui: &Rc<Ui>, path: PathBuf, login: bool| {
                let button = button.clone();
                if let Some(panel) = ui.settings_panel.borrow().as_ref() {
                    panel.busy(true);
                }
                ui.button_task(
                    &button,
                    "恢复中…",
                    move |service| service.restore_backup_form(&path, login),
                    |ui, result| {
                        if let Some(panel) = ui.settings_panel.borrow().as_ref() {
                            panel.busy(false);
                            panel.sync_autostart(&ui.service);
                        }
                        match result {
                            Ok((subscriptions, rules)) => {
                                ui.notify(&format!("已恢复 {subscriptions} 个订阅、{rules} 个规则"));
                                let settings = ui.service.snapshot().settings;
                                ui.apply_font_size(settings.font_size);
                                apply_theme(&settings.theme);
                                ui.refresh(Page::Settings);
                            }
                            Err(error) => ui.error("恢复备份失败", format!("{error:#}")),
                        }
                    },
                );
            });
            let ready = Rc::new(move |ui: &Rc<Ui>, login: bool| {
                let dialog = alert_dialog(
                    "合并恢复备份？",
                    "保留现有订阅和规则并添加备份副本，当前设置将被备份替换。运行中的连接会先校验新配置，失败则保留原连接。",
                );
                dialog.add_response("cancel", "取消");
                dialog.add_response("restore", "选择备份");
                dialog.set_response_appearance("restore", adw::ResponseAppearance::Suggested);
                dialog.set_body("备份含明文节点凭据与订阅地址，请只选择可信的本机备份。\n合并恢复保留现有资源；登录启动和窗口尺寸保留本机设置。");
                dialog.set_close_response("cancel");
                let weak = Rc::downgrade(ui);
                let restore_file = restore_file.clone();
                dialog.connect_response(None, move |dialog, response| {
                    let Some(ui) = weak.upgrade() else {
                        return;
                    };
                    if !ui.finish_settings_prompt(dialog) || response != "restore" {
                        return;
                    }
                    #[cfg(feature = "ui-smoke")]
                    if let Some(dir) = ui.smoke_dir.borrow().clone() {
                        restore_file(&ui, dir.join("smoke-backup.json"), login);
                        return;
                    }
                    let chooser = gtk::FileDialog::builder().title("选择 AeroBox 备份").build();
                    let weak = Rc::downgrade(&ui);
                    let restore_file = restore_file.clone();
                    chooser.open(Some(&ui.window), None::<&gio::Cancellable>, move |result| {
                        let (Ok(file), Some(ui)) = (result, weak.upgrade()) else {
                            return;
                        };
                        let Some(path) = file.path() else {
                            return;
                        };
                        restore_file(&ui, path, login);
                    });
                });
                ui.settings_prompt.replace(Some(dialog.clone()));
                dialog.present(Some(&ui.window));
            });
            SettingsPanel::request_save(&ui, "合并恢复备份", ready);
        });
        let weak = Rc::downgrade(self);
        let saved = settings.clone();
        let read = Rc::new({
            let autostart = autostart.clone();
            move || {
                let next = model::Settings {
                    font_size: model::FONT_SIZE_MIN + font_size.selected(),
                    theme: match theme.selected() {
                        1 => "light",
                        2 => "dark",
                        _ => "system",
                    }
                    .into(),
                    system_proxy: proxy.is_active(),
                    ipv6: ipv6.is_active(),
                    bypass_lan: bypass.is_active(),
                    sniff: sniff.is_active(),
                    dns_hijack: hijack.is_active(),
                    dns_cache: cache.is_active(),
                    direct_dns: direct_dns.text().trim().into(),
                    remote_dns: remote_dns.text().trim().into(),
                    auto_detect_ip: detect_ip.is_active(),
                    tun_mtu: mtu.text().trim().parse().unwrap_or(0),
                    log_level: levels[log.selected() as usize].into(),
                    test_url: test_url.text().trim().into(),
                    test_timeout: timeout.text().trim().parse().unwrap_or(0),
                    ..saved.clone()
                };
                (next, autostart.is_active())
            }
        });
        let baseline = RefCell::new({
            let mut current = read();
            current.0 = self.service.snapshot().settings;
            current
        });
        let panel = Rc::new(SettingsPanel {
            save: save.clone(),
            form,
            autostart: autostart.clone(),
            read: read.clone(),
            baseline,
            is_dirty: Cell::new(false),
            saving: Cell::new(false),
        });
        let update_dirty = {
            let panel = Rc::downgrade(&panel);
            Rc::new(move || {
                if let Some(panel) = panel.upgrade() {
                    panel.update_dirty();
                }
            })
        };
        for widget in descendants(&self.body) {
            if let Some(row) = widget.downcast_ref::<adw::SwitchRow>() {
                let update = update_dirty.clone();
                row.connect_active_notify(move |_| update());
            } else if let Some(row) = widget.downcast_ref::<adw::ComboRow>() {
                let update = update_dirty.clone();
                row.connect_selected_notify(move |_| update());
            } else if let Some(entry) = widget.downcast_ref::<gtk::Entry>() {
                let update = update_dirty.clone();
                entry.connect_changed(move |_| update());
            }
        }
        panel.update_dirty();
        self.settings_panel.replace(Some(panel.clone()));
        let panel = Rc::downgrade(&panel);
        save.connect_clicked(move |_| {
            if let (Some(ui), Some(panel)) = (weak.upgrade(), panel.upgrade()) {
                panel.save(&ui);
            }
        });
    }
}
#[cfg(feature = "ui-smoke")]
pub(super) fn smoke_general(ui: &Rc<Ui>) -> Result<()> {
    let panel = ui.settings_panel.borrow().clone().context("缺少设置页")?;
    let content = descendants(&panel.form);
    anyhow::ensure!(
        !content
            .iter()
            .any(|widget| widget.is::<gtk::StackSwitcher>()),
        "设置仍有标签页"
    );
    anyhow::ensure!(
        content.iter().any(|widget| widget
            .downcast_ref::<adw::ComboRow>()
            .is_some_and(|row| row.title() == "日志级别"))
            && content
                .iter()
                .any(|widget| widget.widget_name() == "connection-diagnostics"),
        "常规设置缺少日志级别或连接诊断"
    );
    Ok(())
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

#[cfg(feature = "ui-smoke")]
fn smoke_data_button(ui: &Rc<Ui>, title: &str) -> Result<gtk::Button> {
    let row = descendants(&ui.body)
        .iter()
        .filter_map(|widget| widget.clone().downcast::<adw::ActionRow>().ok())
        .find(|row| row.title().as_str() == title)
        .with_context(|| format!("缺少设置项 {title}"))?;
    descendants(&row)
        .iter()
        .filter_map(|widget| widget.clone().downcast::<gtk::Button>().ok())
        .next()
        .with_context(|| format!("设置项 {title} 没有操作按钮"))
}

#[cfg(feature = "ui-smoke")]
async fn smoke_respond(ui: &Ui, response: &str) -> Result<()> {
    let dialog = ui
        .settings_prompt
        .borrow()
        .clone()
        .context("缺少设置确认框")?;
    anyhow::ensure!(dialog.has_response(response), "确认框缺少操作 {response}");
    let label = dialog.response_label(response);
    let button = descendants(&dialog)
        .into_iter()
        .filter_map(|widget| widget.downcast::<gtk::Button>().ok())
        .find(|button| button.label().as_ref() == Some(&label))
        .with_context(|| format!("缺少确认按钮「{label}」"))?;
    let start = std::time::Instant::now();
    loop {
        if button.is_mapped()
            && button.is_sensitive()
            && button.width() > 0
            && button.height() > 0
            && let Some(bounds) = button.compute_bounds(&ui.window)
            && let Some(hit) = ui.window.pick(
                f64::from(bounds.x() + bounds.width() / 2.0),
                f64::from(bounds.y() + bounds.height() / 2.0),
                gtk::PickFlags::DEFAULT,
            )
            && (hit == *button.upcast_ref::<gtk::Widget>() || hit.is_ancestor(&button))
        {
            button.emit_clicked();
            return Ok(());
        }
        anyhow::ensure!(
            start.elapsed() < Duration::from_secs(5),
            "确认按钮「{label}」未能显示"
        );
        glib::timeout_future(Duration::from_millis(16)).await;
    }
}

#[cfg(feature = "ui-smoke")]
pub(super) fn smoke_section(ui: &Ui, section: &str) -> Result<()> {
    let title = match section {
        "general" => "外观与启动",
        "network" => "DNS",
        "tun" => "虚拟网卡",
        _ => anyhow::bail!("未知设置分组"),
    };
    let group = descendants(&ui.body)
        .into_iter()
        .filter_map(|widget| widget.downcast::<adw::PreferencesGroup>().ok())
        .find(|group| group.title() == title)
        .context("缺少设置分组")?;
    if let Some(bounds) = group.compute_bounds(&ui.body) {
        ui.scroll.vadjustment().set_value(f64::from(bounds.y()));
    }
    Ok(())
}

#[cfg(feature = "ui-smoke")]
pub(super) async fn smoke_data_action(ui: &Rc<Ui>, step: u32) -> Result<()> {
    use anyhow::ensure;
    match step {
        0 => {
            smoke_edit(ui)?;
            let before = ui.service.snapshot().settings;
            ensure!(
                before.font_size != model::FONT_SIZE_MAX,
                "测试基线字体不应已是最大值"
            );
            smoke_data_button(ui, "导出备份")?.emit_clicked();
            smoke_respond(ui, "save").await?;
            ensure!(ui.jobs.get() > 0, "保存并继续没有启动保存");
        }
        1 => {
            ensure!(ui.jobs.get() == 0, "保存并导出未完成");
            ensure!(
                ui.settings_prompt.borrow().is_none(),
                "保存后仍有未保存提示"
            );
            let settings = ui.service.snapshot().settings;
            ensure!(
                settings.font_size == model::FONT_SIZE_MAX
                    && settings.direct_dns == "tcp://223.5.5.5:5353"
                    && settings.remote_dns == "tls://one.one.one.one",
                "保存并导出覆盖了其他设置"
            );
            let path = ui
                .smoke_dir
                .borrow()
                .as_ref()
                .context("缺少备份自检目录")?
                .join("smoke-backup.json");
            let backup: serde_json::Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            ensure!(
                backup["format"] == "aerobox-linux-backup"
                    && backup["settings"]["remote_dns"] == settings.remote_dns
                    && backup["subscriptions"]
                        .as_array()
                        .is_some_and(|items| !items.is_empty()),
                "保存并导出没有生成有效备份"
            );
        }
        2 => {
            let before = ui.service.snapshot();
            smoke_data_button(ui, "恢复默认设置")?.emit_clicked();
            smoke_respond(ui, "reset").await?;
            smoke_saving(ui)?;
            ensure!(before.subscriptions.len() == ui.service.snapshot().subscriptions.len());
        }
        3 => {
            ensure!(ui.jobs.get() == 0, "恢复默认设置尚未完成");
            smoke_restored(ui)?;
            ensure!(
                ui.settings_prompt.borrow().is_none(),
                "恢复默认确认框未关闭"
            );
            let after = ui.service.snapshot();
            let defaults = model::Settings::default();
            ensure!(
                after.settings.font_size == defaults.font_size
                    && after.settings.direct_dns == defaults.direct_dns
                    && after.settings.remote_dns == defaults.remote_dns,
                "恢复默认没有持久化"
            );
            ensure!(
                !after.settings.active_subscription.is_empty(),
                "恢复默认清空了当前订阅"
            );
        }
        4 => {
            smoke_data_button(ui, "合并恢复备份")?.emit_clicked();
            smoke_respond(ui, "restore").await?;
            ensure!(ui.jobs.get() > 0, "选择备份后没有执行合并恢复");
        }
        _ => unreachable!(),
    }
    Ok(())
}

#[cfg(feature = "ui-smoke")]
pub(super) async fn smoke_autostart(ui: &Rc<Ui>, step: u32) -> Result<()> {
    use anyhow::ensure;
    ensure!(ui.jobs.get() == 0, "设置操作尚未完成");
    if step == 0 {
        // Only Weak handles survive navigation, including all signal closures.
        for _ in 0..10 {
            let panel = Rc::downgrade(ui.settings_panel.borrow().as_ref().context("缺少设置页")?);
            ui.navigate(Page::Home);
            ensure!(panel.upgrade().is_none(), "离开设置页后控制器未释放");
            ui.navigate(Page::Settings);
        }
    }
    let expected_login = matches!(step, 1 | 2);
    ensure!(
        ui.service.autostart_enabled() == expected_login,
        "设置操作错误地改变了登录自启动: step={step}"
    );
    match step {
        0 | 2 | 4 => {
            let panel = ui
                .settings_panel
                .borrow()
                .as_ref()
                .cloned()
                .context("缺少设置页")?;
            panel.autostart.set_active(!expected_login);
            ensure!(panel.is_dirty.get(), "修改登录自启动没有标记未保存");
            smoke_data_button(
                ui,
                if step == 2 {
                    "合并恢复备份"
                } else {
                    "恢复默认设置"
                },
            )?
            .emit_clicked();
            smoke_respond(ui, if step == 4 { "discard" } else { "save" }).await?;
        }
        1 | 5 => smoke_respond(ui, "reset").await?,
        3 => smoke_respond(ui, "restore").await?,
        6 => smoke_restored(ui)?,
        _ => unreachable!(),
    }
    Ok(())
}

#[cfg(feature = "ui-smoke")]
pub(super) async fn smoke_network(ui: &Ui) -> Result<()> {
    let widgets = descendants(&ui.body);
    let mut entries = Vec::new();
    for (title, expected) in [
        ("直连 DNS", "tcp://223.5.5.5:5353"),
        ("远程 DNS", "tls://one.one.one.one"),
    ] {
        let entry = widgets
            .iter()
            .filter_map(|widget| widget.clone().downcast::<gtk::Entry>().ok())
            .find(|entry| entry.placeholder_text().as_deref() == Some(title))
            .with_context(|| format!("缺少 DNS 输入 {title}"))?;
        anyhow::ensure!(entry.text() == expected, "{title} 未恢复备份值");
        entries.push(entry);
    }
    let viewport = ui.scroll.child().context("设置页缺少滚动视口")?;
    let adjustment = ui.scroll.vadjustment();
    let start = std::time::Instant::now();
    loop {
        let bounds: Option<Vec<_>> = entries
            .iter()
            .map(|entry| {
                entry
                    .is_mapped()
                    .then(|| entry.compute_bounds(&viewport))
                    .flatten()
                    .filter(|rect| rect.height() > 0.0)
            })
            .collect();
        if ui.window.visible_dialog().is_none()
            && let Some(bounds) = bounds
        {
            let top = f64::from(bounds[0].y());
            let bottom = f64::from(bounds[1].y() + bounds[1].height());
            let height = f64::from(viewport.height());
            if top >= 0.0 && bottom <= height {
                return Ok(());
            }
            anyhow::ensure!(
                start.elapsed() < Duration::from_secs(5),
                "DNS 输入框未完整显示：直连顶部 {top}，远程底部 {bottom}，视口高度 {height}"
            );
            let value = adjustment.value();
            adjustment.clamp_page(value + top.floor(), value + bottom.ceil());
        }
        anyhow::ensure!(
            start.elapsed() < Duration::from_secs(5),
            "弹窗未关闭或 DNS 输入框尚未布局"
        );
        glib::timeout_future(Duration::from_millis(16)).await;
    }
}

#[cfg(feature = "ui-smoke")]
pub(super) async fn smoke_tun_settings(ui: &Rc<Ui>) -> Result<()> {
    use anyhow::ensure;
    let widgets = descendants(&ui.body);
    ensure!(
        !widgets
            .iter()
            .any(|widget| widget.is::<gtk::StackSwitcher>()),
        "设置仍有标签页"
    );
    ensure!(
        !widgets
            .iter()
            .filter_map(|w| w.downcast_ref::<adw::ActionRow>())
            .any(|row| matches!(row.title().as_str(), "网络权限" | "启用 TUN")),
        "设置仍有重复的 TUN 控件"
    );
    let panel = ui.settings_panel.borrow().clone().context("缺少设置页")?;
    let mtu = widgets
        .iter()
        .filter_map(|w| w.downcast_ref::<gtk::Entry>())
        .find(|entry| entry.placeholder_text().as_deref() == Some("MTU"))
        .context("缺少 MTU")?;
    let original = ui.service.snapshot().settings;
    for value in [
        if original.tun_mtu == 1400 { 1500 } else { 1400 },
        original.tun_mtu,
    ] {
        mtu.set_text(&value.to_string());
        panel.save.emit_clicked();
        smoke_saving(ui)?;
        let start = std::time::Instant::now();
        while ui.jobs.get() > 0 {
            ensure!(start.elapsed() < Duration::from_secs(5), "保存 MTU 超时");
            glib::timeout_future(Duration::from_millis(16)).await;
        }
        let saved = ui.service.snapshot().settings;
        ensure!(
            saved.tun_mtu == value && saved.tun_enabled == original.tun_enabled,
            "保存 MTU 改变了 TUN 开关"
        );
        ensure!(
            ui.settings_panel
                .borrow()
                .as_ref()
                .is_some_and(|p| Rc::ptr_eq(p, &panel)),
            "保存重建了设置表单"
        );
    }
    Ok(())
}

#[cfg(feature = "ui-smoke")]
pub(super) async fn smoke_unsaved(ui: &Rc<Ui>, response: Option<&str>) -> Result<()> {
    if let Some(response) = response {
        anyhow::ensure!(ui.page.get() == Page::Settings, "确认前已离开设置页");
        anyhow::ensure!(
            ui.pending_leave.borrow().is_some(),
            "离开确认没有保存目标页面"
        );
        return smoke_respond(ui, response).await;
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

#[cfg(feature = "ui-smoke")]
pub(super) fn smoke_save_bounds(ui: &Rc<Ui>) -> Result<()> {
    use anyhow::ensure;
    let save = descendants(&ui.floating)
        .into_iter()
        .filter_map(|w| w.downcast::<gtk::Button>().ok())
        .find(|button| button.widget_name() == "settings-save")
        .context("缺少悬浮保存按钮")?;
    ensure!(
        save.is_visible() && save.is_sensitive(),
        "修改后没有显示悬浮保存按钮"
    );
    let bounds = save
        .compute_bounds(&ui.floating)
        .context("悬浮保存按钮没有位置")?;
    ensure!(
        bounds.x() > ui.floating.width() as f32 - bounds.width() - 56.0
            && bounds.x() + bounds.width() <= ui.floating.width() as f32
            && bounds.y() > ui.floating.height() as f32 - bounds.height() - 56.0
            && bounds.y() + bounds.height() <= ui.floating.height() as f32,
        "保存按钮不在右下角: bounds={bounds:?}, overlay={}x{}",
        ui.floating.width(),
        ui.floating.height(),
    );
    Ok(())
}

#[cfg(feature = "ui-smoke")]
fn smoke_saving(ui: &Rc<Ui>) -> Result<()> {
    use anyhow::ensure;
    let panel = ui.settings_panel.borrow();
    let panel = panel.as_ref().context("缺少设置页")?;
    ensure!(ui.jobs.get() > 0 && panel.saving.get(), "保存任务没有启动");
    ensure!(
        panel.save.is_visible() && !panel.save.is_sensitive(),
        "保存期间按钮不可见或允许重复保存"
    );
    ensure!(
        descendants(&panel.save)
            .into_iter()
            .filter_map(|widget| widget.downcast::<gtk::Spinner>().ok())
            .any(|spinner| spinner.is_visible() && spinner.is_spinning()),
        "保存按钮内没有工作中的进度指示器"
    );
    Ok(())
}

#[cfg(feature = "ui-smoke")]
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
        saved.same_preferences(&ui.service.snapshot().settings),
        "设置基线与持久化值不一致"
    );
    let widgets = descendants(&ui.body);
    let mtu = widgets
        .iter()
        .filter_map(|widget| widget.clone().downcast::<gtk::Entry>().ok())
        .find(|entry| entry.placeholder_text().as_deref() == Some("MTU"))
        .context("缺少 MTU 输入")?;
    mtu.set_text(&(saved.tun_mtu + 100).to_string());
    ensure!(panel.is_dirty.get(), "修改后没有未保存标记");
    ensure!(panel.save.is_sensitive(), "修改后保存按钮没有启用");
    mtu.set_text(&saved.tun_mtu.to_string());
    ensure!(
        !panel.is_dirty.get(),
        "改回原值仍显示未保存: current={:?}, saved={:?}",
        (panel.read)(),
        panel.baseline.borrow()
    );
    ensure!(!panel.save.is_sensitive(), "改回原值仍可以保存");
    mtu.set_text(&(saved.tun_mtu + 100).to_string());
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

#[cfg(feature = "ui-smoke")]
pub(super) fn smoke_restored(ui: &Rc<Ui>) -> Result<()> {
    let saved = ui.service.snapshot().settings;
    anyhow::ensure!(
        ui.typography.preview() == saved.font_size,
        "界面字体与已保存的设置不一致"
    );
    anyhow::ensure!(
        adw::StyleManager::default().color_scheme()
            == match saved.theme.as_str() {
                "light" => adw::ColorScheme::ForceLight,
                "dark" => adw::ColorScheme::ForceDark,
                _ => adw::ColorScheme::Default,
            },
        "界面主题与已保存的设置不一致"
    );
    let widgets = descendants(&ui.body);
    for (title, selected) in [
        ("字体大小", saved.font_size - model::FONT_SIZE_MIN),
        (
            "外观",
            match saved.theme.as_str() {
                "light" => 1,
                "dark" => 2,
                _ => 0,
            },
        ),
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

#[cfg(feature = "ui-smoke")]
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

#[cfg(feature = "ui-smoke")]
pub(super) fn smoke_fullscreen_settings(ui: &Rc<Ui>) -> Result<()> {
    use anyhow::ensure;
    ensure!(ui.page.get() == Page::Settings, "设置页未打开");
    let panel = ui
        .settings_panel
        .borrow()
        .clone()
        .context("缺少设置控制器")?;
    let Some(row_height) = smoke_row_height(ui) else {
        anyhow::bail!("缺少设置行")
    };
    ensure!(row_height >= 56, "全屏控件没有跟随密度增大: {row_height}");
    ensure!(
        panel.form.width() > 1000 && panel.form.width() <= ui.body.width(),
        "全屏设置内容宽度不合理"
    );
    let fields: Vec<_> = descendants(&panel.form)
        .into_iter()
        .filter(|widget| widget.has_css_class("labeled-entry"))
        .collect();
    ensure!(fields.len() >= 2, "缺少成对输入框");
    for field in &fields {
        let caption = field
            .first_child()
            .and_then(|child| child.downcast::<gtk::Label>().ok())
            .context("缺少固定输入框标题")?;
        let entry = descendants(field)
            .into_iter()
            .filter_map(|widget| widget.downcast::<gtk::Entry>().ok())
            .next()
            .context("缺少输入框")?;
        let caption_bounds = caption.compute_bounds(field).context("标题未布局")?;
        let entry_bounds = entry.compute_bounds(field).context("输入框未布局")?;
        ensure!(
            caption_bounds.y() >= 0.0
                && entry_bounds.y() >= caption_bounds.y() + caption_bounds.height(),
            "固定标题和输入框位置不正确"
        );
    }
    Ok(())
}

#[cfg(feature = "ui-smoke")]
pub(super) fn smoke_settings(ui: &Rc<Ui>, verify: bool) -> Result<()> {
    use anyhow::ensure;
    // The save button floats over the page overlay, outside `ui.body`.
    let widgets = descendants(&ui.floating);
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
                && !settings.dns_cache
                && !settings.tun_enabled
                && settings.tun_mtu == 1400
                && settings.direct_dns == "tcp://223.5.5.5:5353"
                && settings.remote_dns == "tls://one.one.one.one",
            "设置控件没有持久化"
        );
        ensure!(!ui.service.status().running, "设置测试意外启动了连接");
        ensure!(
            !save.is_visible() && !save.is_sensitive(),
            "保存完成后仍显示悬浮保存按钮"
        );
        ensure!(
            !descendants(save).iter().any(|w| w.is::<gtk::Spinner>()),
            "保存完成后仍有进度指示器"
        );
        return Ok(());
    }
    let body = descendants(&ui.body);
    for (title, value) in [("IPv6", false), ("DNS 缓存", false)] {
        let row = body
            .iter()
            .filter_map(|w| w.clone().downcast::<adw::SwitchRow>().ok())
            .find(|row| row.title() == title)
            .with_context(|| format!("缺少开关 {title}"))?;
        row.set_active(value);
    }
    ensure!(
        !body.iter().any(|widget| widget
            .downcast_ref::<adw::ComboRow>()
            .is_some_and(|row| row.title() == "协议栈")),
        "设置包含不适用的协议栈选项"
    );
    let mtu = body
        .iter()
        .filter_map(|w| w.clone().downcast::<gtk::Entry>().ok())
        .find(|entry| entry.placeholder_text().as_deref() == Some("MTU"))
        .context("缺少 MTU 输入")?;
    ensure!(mtu.is_sensitive(), "无法设置 MTU");
    mtu.set_text("1400");
    body.iter()
        .filter_map(|w| w.clone().downcast::<adw::ComboRow>().ok())
        .find(|row| row.title() == "字体大小")
        .context("缺少字体大小控件")?
        .set_selected(model::FONT_SIZE_MAX - model::FONT_SIZE_MIN);
    for (title, text) in [
        ("直连 DNS", "tcp://223.5.5.5:5353"),
        ("远程 DNS", "tls://one.one.one.one"),
    ] {
        body.iter()
            .filter_map(|widget| widget.clone().downcast::<gtk::Entry>().ok())
            .find(|entry| entry.placeholder_text().as_deref() == Some(title))
            .with_context(|| format!("缺少 DNS 输入 {title}"))?
            .set_text(text);
    }
    save.emit_clicked();
    smoke_saving(ui)?;
    let scroll = ui
        .body
        .ancestor(gtk::ScrolledWindow::static_type())
        .and_then(|w| w.downcast::<gtk::ScrolledWindow>().ok())
        .context("缺少设置滚动区域")?;
    scroll.vadjustment().set_value(1000.0);
    Ok(())
}
