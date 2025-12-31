use leptos::ev::KeyboardEvent;
use leptos::html::Input;
use leptos::prelude::*;

#[component]
pub fn OtpInput(
    /// The number of digits in the OTP (default: 6)
    #[prop(default = 6)]
    digit_count: usize,
    /// Callback when OTP is complete
    on_complete: Callback<String>,
    /// Optional callback for each digit change
    #[prop(optional)]
    on_change: Option<Callback<String>>,
    /// Whether the input is disabled
    #[prop(optional, into)]
    disabled: MaybeProp<bool>,
) -> impl IntoView {
    let (otp_values, set_otp_values) = signal(vec![String::new(); digit_count]);

    // Store input refs in a way that can be shared across closures
    let input_refs = StoredValue::new(
        (0..digit_count)
            .map(|_| NodeRef::<Input>::new())
            .collect::<Vec<_>>(),
    );

    view! {
        <div class="flex gap-2 justify-center">
            {(0..digit_count)
                .map(|index| {
                    let input_ref = input_refs.with_value(|refs| refs[index]);
                    let handle_input = move |ev| {
                        let value = event_target_value(&ev);
                        let mut values = otp_values.get();
                        let new_value = if value.len() > 1 {
                            value.chars().last().unwrap_or_default().to_string()
                        } else {
                            value
                        };
                        if !new_value.is_empty() && !new_value.chars().all(|c| c.is_ascii_digit()) {
                            return;
                        }
                        values[index] = new_value.clone();
                        set_otp_values.set(values.clone());
                        if let Some(on_change_cb) = on_change {
                            let full_otp = values.join("");
                            on_change_cb.run(full_otp.clone());
                        }
                        if !new_value.is_empty() && index < digit_count - 1 {
                            input_refs
                                .with_value(|refs| {
                                    if let Some(next_input) = refs.get(index + 1) {
                                        if let Some(element) = next_input.get() {
                                            let _ = element.focus();
                                        }
                                    }
                                });
                        }
                        if values.iter().all(|v| !v.is_empty()) {
                            let full_otp = values.join("");
                            on_complete.run(full_otp);
                        }
                    };
                    let handle_keydown = move |event: KeyboardEvent| {
                        let key = event.key();
                        if key == "Backspace" {
                            let mut values = otp_values.get();
                            if values[index].is_empty() && index > 0 {
                                values[index - 1] = String::new();
                                set_otp_values.set(values);
                                input_refs
                                    .with_value(|refs| {
                                        if let Some(prev_input) = refs.get(index - 1) {
                                            if let Some(element) = prev_input.get() {
                                                let _ = element.focus();
                                            }
                                        }
                                    });
                            } else {
                                values[index] = String::new();
                                set_otp_values.set(values);
                            }
                            event.prevent_default();
                        } else if key == "ArrowLeft" && index > 0 {
                            input_refs
                                .with_value(|refs| {
                                    if let Some(prev_input) = refs.get(index - 1) {
                                        if let Some(element) = prev_input.get() {
                                            let _ = element.focus();
                                        }
                                    }
                                });
                        } else if key == "ArrowRight" && index < digit_count - 1 {
                            input_refs
                                .with_value(|refs| {
                                    if let Some(next_input) = refs.get(index + 1) {
                                        if let Some(element) = next_input.get() {
                                            let _ = element.focus();
                                        }
                                    }
                                });
                        }
                    };

                    // Take only the last character if multiple are pasted

                    // Only accept digits

                    // Call on_change callback if provided

                    // Move to next input if value is entered

                    // Check if OTP is complete

                    // If current input is empty, move to previous input and clear it

                    // Clear current input

                    view! {
                        <input
                            type="text"
                            inputmode="numeric"
                            maxlength="1"
                            class="w-12 h-14 text-center text-2xl font-semibold border-2 border-gray-300 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-200 focus:outline-none transition-all disabled:bg-gray-100 disabled:cursor-not-allowed"
                            node_ref=input_ref
                            prop:value=move || otp_values.get()[index].clone()
                            on:input=handle_input
                            on:keydown=handle_keydown
                            prop:disabled=move || disabled.get().unwrap_or(false)
                        />
                    }
                })
                .collect_view()}
        </div>
    }
}
