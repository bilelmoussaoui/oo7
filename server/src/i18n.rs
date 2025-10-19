use gettextrs::gettext;

fn freplace(input: String, args: &[&str]) -> String {
    let mut parts = input.split("{}");
    let mut output = parts.next().unwrap_or("").to_string();
    for (p, a) in parts.zip(args.iter()) {
        output += &(a.to_string() + p);
    }
    output
}

pub(crate) fn i18n_f(format: &str, args: &[&str]) -> String {
    let s = gettext(format);
    freplace(s, args)
}
