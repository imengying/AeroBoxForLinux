use super::*;

/// Recovery starts from fresh defaults; old schemas are never interpreted.
pub fn recover_store(
    dir: Option<PathBuf>,
    mut error: anyhow::Error,
) -> Result<Option<model::Store>> {
    adw::init().context("无法初始化 Wayland 界面")?;
    let path = dir
        .clone()
        .map(Ok)
        .unwrap_or_else(|| model::config_home().map(|p| p.join("AeroBoxForLinux")))?
        .join("state.json");
    loop {
        let window = adw::Window::builder()
            .title("AeroBox")
            .default_width(560)
            .default_height(450)
            .build();
        window.set_widget_name("startup-recovery");
        let root = gtk::Box::new(gtk::Orientation::Vertical, 0);
        root.append(&adw::HeaderBar::new());
        let content = gtk::Box::new(gtk::Orientation::Vertical, 18);
        margin(&content, 28, 28, 12, 28);
        let heading = label("无法读取应用数据", "title-2");
        heading.set_wrap(true);
        content.append(&heading);
        let explanation = gtk::Label::builder()
            .label(format!(
                "{error:#}\n\n位置：{}\n\n重置会备份当前数据，重新建立订阅、规则和设置。已安装的内核会保留。",
                path.display()
            ))
            .xalign(0.0)
            .wrap(true)
            .wrap_mode(gtk::pango::WrapMode::WordChar)
            .selectable(true)
            .build();
        content.append(&explanation);
        let scroll = gtk::ScrolledWindow::builder()
            .hscrollbar_policy(gtk::PolicyType::Never)
            .vexpand(true)
            .child(&content)
            .build();
        root.append(&scroll);
        let actions = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        actions.set_halign(gtk::Align::End);
        margin(&actions, 28, 28, 12, 24);
        let cancel = gtk::Button::with_label("退出");
        cancel.set_widget_name("recovery-exit");
        let reset_button = gtk::Button::with_label("备份并重置");
        reset_button.set_widget_name("recovery-reset");
        reset_button.add_css_class("destructive-action");
        actions.append(&cancel);
        actions.append(&reset_button);
        root.append(&actions);
        window.set_content(Some(&root));
        let reset = Rc::new(Cell::new(false));
        let response = reset.clone();
        let main_loop = glib::MainLoop::new(None, false);
        let response_loop = main_loop.clone();
        reset_button.connect_clicked(move |_| {
            response.set(true);
            response_loop.quit();
        });
        let weak_window = window.downgrade();
        cancel.connect_clicked(move |_| {
            if let Some(window) = weak_window.upgrade() {
                window.close();
            }
        });
        let close_loop = main_loop.clone();
        window.connect_close_request(move |_| {
            close_loop.quit();
            glib::Propagation::Proceed
        });
        window.present();
        main_loop.run();
        window.close();
        if !reset.get() {
            return Ok(None);
        }
        match model::Store::reset(dir.clone()) {
            Ok((store, backup)) => {
                if let Some(backup) = backup {
                    eprintln!("原数据已备份至 {}", backup.display());
                }
                return Ok(Some(store));
            }
            Err(failure) => error = failure.context("重置失败"),
        }
    }
}

pub(super) fn smoke_recovery() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.json");
    let original = b"unreadable-state-fixture";
    std::fs::write(&path, original)?;
    for answer in ["exit", "reset"] {
        let clicked = Rc::new(Cell::new(false));
        let answered = clicked.clone();
        let callback = glib::timeout_add_local(Duration::from_millis(50), move || {
            fn choose(widget: &gtk::Widget, name: &str) -> bool {
                if widget.widget_name() == name
                    && let Some(button) = widget.downcast_ref::<gtk::Button>()
                {
                    button.emit_clicked();
                    return true;
                }
                let mut child = widget.first_child();
                while let Some(widget) = child {
                    child = widget.next_sibling();
                    if choose(&widget, name) {
                        return true;
                    }
                }
                false
            }
            for window in gtk::Window::list_toplevels() {
                if window.widget_name() == "startup-recovery"
                    && choose(window.upcast_ref(), &format!("recovery-{answer}"))
                {
                    answered.set(true);
                    return glib::ControlFlow::Break;
                }
            }
            glib::ControlFlow::Continue
        });
        let result = recover_store(
            Some(directory.path().into()),
            anyhow::anyhow!("界面测试：无法读取数据"),
        );
        if !clicked.get() {
            callback.remove();
            anyhow::bail!("恢复对话框没有完成交互");
        }
        let result = result?;
        if answer == "exit" {
            anyhow::ensure!(result.is_none(), "取消恢复后仍然重置了数据");
            anyhow::ensure!(std::fs::read(&path)? == original, "取消恢复改写了数据");
        } else {
            let store = result.context("重置没有创建新数据")?;
            anyhow::ensure!(store.state.subscriptions.is_empty(), "重置仍含有旧订阅");
            anyhow::ensure!(
                store.state.settings.log_level == "error",
                "重置默认设置错误"
            );
            let backup = std::fs::read_dir(directory.path())?
                .filter_map(|entry| entry.ok())
                .find(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("state.backup-")
                })
                .context("重置前未保留原文件")?;
            anyhow::ensure!(std::fs::read(backup.path())? == original, "备份不完整");
        }
    }
    Ok(())
}
