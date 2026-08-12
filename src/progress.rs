/// Basic command-line progress bar.
pub struct Progress {
    total: usize,
    width: usize,
}

impl Progress {
    pub fn new(total: usize, width: usize) -> Self {
        print!("[");
        for _ in 0..width {
            print!(" ");
        }
        print!("]");
        print!("  {} / {} (0%)", 0, total);
        Progress { total: total, width: width }
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
    }

    pub fn done(&self) {
        println!("");
    }
}
