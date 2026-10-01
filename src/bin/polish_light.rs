            .len()
            .saturating_mul(100)
            .checked_div(selection_limit)
            .unwrap_or(0);
        println!(
            "\n🔥 [INFO] ===== LIGHT FILL PROGRESS: {}/{} READY ({}%) | STRICT CHECKS: {} =====\n",
            selected.len(),
            selection_limit,
            fill_percent,
            final_attempts.values().copied().sum::<usize>()
        );