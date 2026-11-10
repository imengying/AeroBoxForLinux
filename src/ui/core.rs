use super::*;

pub(super) struct CorePanel {
    version: adw::ActionRow,
    path: adw::ActionRow,
    status: adw::ActionRow,
    toggle: gtk::Button,
    restart: gtk::Button,
    check: gtk::Button,
    install: gtk::Button,
    pending: Cell<bool>,
    key: RefCell<Option<(String, Option<u32>)>>,
}

impl Ui {
    pub(super) fn core_panel(self: &Rc<Self>, page: &gtk::Box) {
        let group = adw::PreferencesGroup::builder().title("运行状态").build();
        let version = adw::ActionRow::builder()
            .title("sing-box")
            .subtitle("读取中…")
            .build();
        let install = gtk::Button::with_label("下载 / 更新");
        install.set_valign(gtk::Align::Center);
        version.add_suffix(&install);
        group.add(&version);
        let path = adw::ActionRow::builder().title("当前内核").build();
        path.set_subtitle_selectable(true);
        path.set_subtitle_lines(2);
        group.add(&path);
        let status = adw::ActionRow::builder().title("状态").build();
        let toggle = gtk::Button::with_label("启动");
        toggle.set_valign(gtk::Align::Center);
        status.add_suffix(&toggle);
        group.add(&status);
        page.append(&group);
        let actions = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        let check = gtk::Button::with_label("检查配置");
        let restart = gtk::Button::with_label("重启内核");
        let logs = gtk::Button::with_label("查看日志");
        for button in [&check, &restart, &logs] {
            actions.append(button);
        }
        page.append(&actions);
        let panel = Rc::new(CorePanel {
            version,
            path,
            status,
            toggle: toggle.clone(),
            restart: restart.clone(),
            check: check.clone(),
            install: install.clone(),
            pending: Cell::new(false),
            key: RefCell::new(None),
        });
        self.core.replace(Some(panel.clone()));
        panel.tick(self);

        let weak = Rc::downgrade(self);
        toggle.connect_clicked(move |button| {
            if let Some(ui) = weak.upgrade() {
                let running = ui.service.status().running;
                ui.button_task(
                    button,
                    if running {
                        "停止中…"
                    } else {
                        "启动中…"
                    },
                    move |s| if running { s.stop() } else { s.start() },
                    |ui, result| {
                        if let Err(e) = result {
                            ui.error("内核操作失败", format!("{e:#}"));
                        }
                        if let Some(panel) = ui.core.borrow().as_ref() {
                            panel.tick(ui);
                        }
                    },
                );
            }
        });
        let weak = Rc::downgrade(self);
        restart.connect_clicked(move |button| {
            if let Some(ui) = weak.upgrade() {
                ui.button_task(
                    button,
                    "重启中…",
                    |s| s.restart(),
                    |ui, result| {
                        match result {
                            Ok(()) => ui.notify("内核已重启"),
                            Err(e) => ui.error("重启失败", format!("{e:#}")),
                        }
                        if let Some(panel) = ui.core.borrow().as_ref() {
                            panel.tick(ui);
                        }
                    },
                );
            }
        });
        let weak = Rc::downgrade(self);
        check.connect_clicked(move |button| {
            if let Some(ui) = weak.upgrade() {
                ui.button_task(
                    button,
                    "检查中…",
                    |s| {
                        let profile = s.snapshot().settings.active_profile;
                        s.check(&s.generate(&profile)?)
                    },
                    |ui, result| match result {
                        Ok(()) => ui.notify("配置检查通过"),
                        Err(e) => ui.error("配置检查失败", format!("{e:#}")),
                    },
                );
            }
        });
        let weak = Rc::downgrade(self);
        install.connect_clicked(move |button| {
            if let Some(ui) = weak.upgrade() {
                ui.button_task(
                    button,
                    "安装中…",
                    |s| s.install_core(),
                    |ui, result| {
                        match result {
                            Ok(()) => ui.notify("内核已安装"),
                            Err(e) => ui.error("安装失败", format!("{e:#}")),
                        }
                        if let Some(panel) = ui.core.borrow().as_ref() {
                            panel.key.replace(None);
                            panel.tick(ui);
                        }
                    },
                );
            }
        });
        let weak = Rc::downgrade(self);
        logs.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                ui.navigate(Page::Logs);
            }
        });
    }
}

impl CorePanel {
    pub(super) fn tick(self: &Rc<Self>, ui: &Rc<Ui>) {
        let status = ui.service.status();
        let idle = ui.jobs.get() == 0;
        self.toggle.set_sensitive(idle);
        self.restart.set_sensitive(idle && status.running);
        self.check.set_sensitive(idle);
        self.install.set_sensitive(idle && !status.running);
        self.install
            .set_tooltip_text(status.running.then_some("停止内核后可更新"));
        if idle {
            self.toggle
                .set_label(if status.running { "停止" } else { "启动" });
        }
        self.status.set_subtitle(&if status.running {
            format!("运行中 · {}", duration(status.uptime))
        } else {
            "已停止".into()
        });
        let key = (ui.service.snapshot().settings.core_path, status.pid);
        if !idle || self.key.borrow().as_ref() == Some(&key) || self.pending.replace(true) {
            return;
        }
        self.key.replace(Some(key));
        self.version.set_subtitle("读取中…");
        let service = ui.service.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let binary = service.core_binary();
            let _ = tx.send((binary, service.core_info()));
        });
        let weak = Rc::downgrade(self);
        glib::timeout_add_local(Duration::from_millis(100), move || {
            let Some(panel) = weak.upgrade() else {
                return glib::ControlFlow::Break;
            };
            let (binary, result) = match rx.try_recv() {
                Ok(result) => result,
                Err(mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
                Err(_) => (
                    Err(anyhow::anyhow!("读取任务已结束")),
                    Err(anyhow::anyhow!("读取任务已结束")),
                ),
            };
            panel.pending.set(false);
            match result {
                Ok(info) => {
                    panel.version.set_subtitle(&info.version);
                    panel.version.set_tooltip_text(None);
                    panel.path.set_subtitle(&info.binary.to_string_lossy());
                    panel.path.set_visible(true);
                }
                Err(error) => {
                    panel.version.set_subtitle(if binary.is_ok() {
                        "无法读取版本"
                    } else {
                        "未安装"
                    });
                    panel.version.set_tooltip_text(Some(&format!("{error:#}")));
                    if let Ok(binary) = binary {
                        panel.path.set_subtitle(&binary.to_string_lossy());
                        panel.path.set_visible(true);
                    } else {
                        panel.path.set_visible(false);
                    }
                }
            }
            glib::ControlFlow::Break
        });
    }
}
