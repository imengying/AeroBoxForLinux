use super::*;

impl Ui {
    pub(super) fn settings(self: &Rc<Self>, heading: &gtk::Box) {
        self.body.add_css_class("settings-page");
        let settings = self.service.snapshot().settings;
        let save = primary("保存", "object-select-symbolic");
        save.set_widget_name("settings-save");
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
        let ads = switch_row("广告拦截", "", settings.block_ads);
        ads.set_tooltip_text(Some("拦截内置基础广告列表中的域名"));
        routing.add(&ads);
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

        let core = group("内核");
        let core_path = adw::EntryRow::builder()
            .title("内核路径（留空自动检测）")
            .text(&settings.core_path)
            .build();
        let browse = icon_button("folder-open-symbolic", "选择 sing-box 内核");
        core_path.add_suffix(&browse);
        let parent = self.window.clone();
        let path_entry = core_path.clone();
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
        core.add(&core_path);
        let current = adw::ActionRow::builder()
            .title("sing-box")
            .subtitle(
                self.service
                    .core_binary()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| "未安装".into()),
            )
            .build();
        let install = gtk::Button::with_label("下载 / 更新");
        install.set_valign(gtk::Align::Center);
        current.add_suffix(&install);
        let weak = Rc::downgrade(self);
        let current_row = current.clone();
        install.connect_clicked(move |button| {
            if let Some(ui) = weak.upgrade() {
                if ui.jobs.get() > 0 {
                    return;
                }
                button.set_sensitive(false);
                let button = button.downgrade();
                let current_row = current_row.clone();
                ui.task(
                    "安装内核",
                    |s| Ok(s.install_core()),
                    move |ui, result| {
                        if let Some(button) = button.upgrade() {
                            button.set_sensitive(true);
                        }
                        match result {
                            Ok(()) => {
                                ui.notify("内核已安装");
                                if let Ok(path) = ui.service.core_binary() {
                                    current_row.set_subtitle(&path.to_string_lossy());
                                }
                            }
                            Err(e) => ui.error("安装失败", format!("{e:#}")),
                        }
                    },
                );
            }
        });
        core.add(&current);
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
        let test_url = adw::EntryRow::builder()
            .title("测试地址")
            .text(&settings.test_url)
            .build();
        testing.add(&test_url);
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
                .title("AeroBox")
                .subtitle(option_env!("AEROBOX_VERSION").unwrap_or(env!("CARGO_PKG_VERSION")))
                .build(),
        );
        general_page.append(&data);
        let weak = Rc::downgrade(self);
        save.connect_clicked(move |button| {
            let Some(ui) = weak.upgrade() else {
                return;
            };
            let mut next = ui.service.snapshot().settings;
            next.theme = match theme.selected() {
                1 => "light",
                2 => "dark",
                _ => "system",
            }
            .into();
            next.core_path = core_path.text().trim().into();
            next.auto_start = auto_core.is_active();
            next.auto_restart = restart.is_active();
            next.system_proxy = proxy.is_active();
            next.ipv6 = ipv6.is_active();
            next.allow_lan = lan.is_active();
            next.bypass_lan = bypass.is_active();
            next.sniff = sniff.is_active();
            next.dns_hijack = hijack.is_active();
            next.dns_cache = cache.is_active();
            next.block_ads = ads.is_active();
            next.auto_detect_ip = detect_ip.is_active();
            next.hardware_acceleration = acceleration.is_active();
            next.update_subscriptions_on_start = update_subs.is_active();
            next.tun_enabled = tun.is_active();
            next.tun_stack = match stack.selected() {
                1 => "gvisor",
                2 => "mixed",
                _ => "system",
            }
            .into();
            next.tun_mtu = mtu.value() as u32;
            next.strict_route = strict.is_active();
            next.log_level = levels[log.selected() as usize].into();
            next.test_url = test_url.text().trim().into();
            next.test_timeout = timeout.value() as u32;
            if let Err(e) = next.validate() {
                ui.error("设置无效", e);
                return;
            }
            let valid_url = url::Url::parse(&next.test_url)
                .is_ok_and(|u| matches!(u.scheme(), "http" | "https") && u.host().is_some());
            if !valid_url {
                ui.error("设置无效", "测速地址须为 HTTP 或 HTTPS 地址");
                return;
            }
            let save_button = button.downgrade();
            let login = autostart.is_active();
            ui.button_task(
                button,
                "保存中…",
                move |s| {
                    s.apply_settings(next)
                        .and_then(|_| platform::set_autostart(login))
                },
                move |ui, result| match result {
                    Ok(()) => {
                        if let Some(button) = save_button.upgrade() {
                            button.set_label("已保存");
                            let weak = button.downgrade();
                            glib::timeout_add_local_once(Duration::from_secs(2), move || {
                                if let Some(button) = weak.upgrade()
                                    && button.is_sensitive()
                                {
                                    button.set_label("保存");
                                }
                            });
                        }
                        ui.notify("设置已保存");
                    }
                    Err(e) => ui.error("保存失败", format!("{e:#}")),
                },
            );
        });
    }
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
                && settings.allow_lan
                && settings.block_ads
                && !settings.dns_cache
                && settings.tun_enabled
                && settings.hardware_acceleration
                && settings.tun_stack == "gvisor"
                && settings.tun_mtu == 1400,
            "设置控件没有持久化"
        );
        ensure!(!ui.service.status().running, "设置测试意外启动了内核");
        ensure!(
            save.is_sensitive() && save.label().as_deref() == Some("已保存"),
            "保存完成没有显示成功状态"
        );
        ensure!(
            !descendants(save).iter().any(|w| w.is::<gtk::Spinner>()),
            "保存完成后仍有进度指示器"
        );
        return Ok(());
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
    for (title, value) in [
        ("IPv6", false),
        ("允许局域网访问", true),
        ("广告拦截", true),
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
