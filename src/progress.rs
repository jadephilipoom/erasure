/// Basic command-line progress bar.
pub struct Progress {
    total: usize,
    width: usize,
    newlines: bool,
}

impl Progress {
    pub fn new(total: usize, width: usize, newlines: bool) -> Self {
        print!("[");
        for _ in 0..width {
            print!(" ");
        }
        print!("]");
        print!("  {} / {} (0%)", 0, total);
        if newlines {
            print!("\n");
        }
        Progress {
            total: total,
            width: width,
            newlines: newlines,
        }
    }

    pub fn update(&self, current: usize) {
        let filled = current * self.width / self.total;
        let mut bar = String::new();
        bar.push('[');
        for i in 0..self.width {
            if i < filled {
                bar.push('=');
            } else {
                bar.push(' ');
            }
        }
        bar.push(']');
        let pct = current * 100 / self.total;
        print!("\r{}  {} / {} ({}%)", bar, current, self.total, pct);
        if self.newlines {
            print!("\n");
        }
    }

    pub fn done(&self) {
        if !self.newlines {
            self.update(self.total);
            print!("\n");
        }
    }
}
