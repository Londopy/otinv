// slow work (zeek, docker, reading big logs, the update check) runs on its
// own thread so the window keeps responding; the screen polls for progress.

use eframe::egui;
use otinv::command::{Event, Step};
use std::sync::mpsc::{channel, Receiver, TryRecvError};
use std::time::Instant;

enum Update<T> {
    Event(Event),
    Done(Result<T, String>),
}

pub struct Job<T> {
    rx: Receiver<Update<T>>,
    pub started: Instant,
    pub step: Option<Step>,
    pub notes: Vec<String>,
}

impl<T: Send + 'static> Job<T> {
    pub fn start(
        ctx: &egui::Context,
        work: impl FnOnce(&mut dyn FnMut(Event)) -> anyhow::Result<T> + Send + 'static,
    ) -> Self {
        let (tx, rx) = channel();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let mut on = |e: Event| {
                let _ = tx.send(Update::Event(e));
                ctx.request_repaint();
            };
            let result = work(&mut on).map_err(|e| format!("{e:#}"));
            let _ = tx.send(Update::Done(result));
            ctx.request_repaint();
        });
        Self {
            rx,
            started: Instant::now(),
            step: None,
            notes: Vec::new(),
        }
    }

    /// Takes in what the worker sent; returns its result once it's done.
    pub fn poll(&mut self) -> Option<Result<T, String>> {
        loop {
            match self.rx.try_recv() {
                Ok(Update::Event(Event::Step(s))) => self.step = Some(s),
                Ok(Update::Event(Event::Note(n))) => self.notes.push(n),
                Ok(Update::Done(r)) => return Some(r),
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => {
                    return Some(Err("the background work stopped unexpectedly".into()))
                }
            }
        }
    }

    /// A spinner, the current step and how long it's been running.
    pub fn show_progress(&self, ui: &mut egui::Ui, what: &str) {
        ui.horizontal(|ui| {
            ui.spinner();
            let step = self.step.map(Step::label).unwrap_or(what);
            let secs = self.started.elapsed().as_secs();
            ui.label(format!("{step}... ({}:{:02})", secs / 60, secs % 60));
        });
        for n in &self.notes {
            ui.label(egui::RichText::new(n).weak());
        }
        // keep the clock moving
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(500));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_job_passes_on_its_steps_and_result() {
        let ctx = egui::Context::default();
        let mut job = Job::start(&ctx, |on| {
            on(Event::Step(Step::Reading));
            on(Event::Note("hello".into()));
            Ok(42)
        });
        let result = loop {
            if let Some(r) = job.poll() {
                break r;
            }
            std::thread::yield_now();
        };
        assert_eq!(result, Ok(42));
        assert_eq!(job.step, Some(Step::Reading));
        assert_eq!(job.notes, ["hello"]);

        let mut failing: Job<()> = Job::start(&ctx, |_| anyhow::bail!("no zeek"));
        let err = loop {
            if let Some(r) = failing.poll() {
                break r;
            }
            std::thread::yield_now();
        };
        assert_eq!(err, Err("no zeek".to_string()));
    }
}
