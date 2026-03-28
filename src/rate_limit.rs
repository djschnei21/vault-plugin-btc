use std::collections::HashMap;
use std::time::Instant;

pub struct RateLimiter {
    requests: HashMap<String, Vec<Instant>>,
    max_requests: usize,
    window: std::time::Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window: std::time::Duration) -> Self {
        Self {
            requests: HashMap::new(),
            max_requests,
            window,
        }
    }

    pub fn check(&mut self, key: &str) -> bool {
        let now = Instant::now();
        let window_start = now - self.window;

        // Clean old requests
        if let Some(reqs) = self.requests.get_mut(key) {
            reqs.retain(|&t| t > window_start);
        }

        let count = self.requests.get(key).map(|r| r.len()).unwrap_or(0);

        if count >= self.max_requests {
            false
        } else {
            self.requests
                .entry(key.to_string())
                .or_insert_with(Vec::new)
                .push(now);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiting() {
        let mut rl = RateLimiter::new(2, std::time::Duration::from_secs(1));

        assert!(rl.check("test"));
        assert!(rl.check("test"));
        assert!(!rl.check("test"));

        // Wait for window
        std::thread::sleep(std::time::Duration::from_secs(2));
        assert!(rl.check("test"));
    }
}
