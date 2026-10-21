//! The interface in English and Russian.
//!
//! Every string is a field of [`Text`], so a missing translation doesn't compile.

use crate::http::Request;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Lang {
    En,
    Ru,
}

/// The cookie that remembers a language picked in the footer.
pub(crate) const COOKIE: &str = "lang";

impl Lang {
    /// The language picked in the footer, else the first supported one the browser asks for.
    pub(crate) fn of(request: &Request) -> Self {
        if let Some(lang) = request.cookie(COOKIE).and_then(Self::from_code) {
            return lang;
        }
        request
            .header("accept-language")
            .unwrap_or_default()
            .split(',')
            .filter(|entry| !entry.trim().ends_with(";q=0"))
            .find_map(|entry| {
                let tag = entry.split(';').next().unwrap_or_default().trim();
                Self::from_code(tag.split('-').next().unwrap_or_default())
            })
            .unwrap_or(Self::En)
    }

    pub(crate) fn from_code(code: &str) -> Option<Self> {
        match code.to_ascii_lowercase().as_str() {
            "en" => Some(Self::En),
            "ru" => Some(Self::Ru),
            _ => None,
        }
    }

    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Ru => "ru",
        }
    }

    /// The other language, offered in the footer under its own name.
    pub(crate) const fn other(self) -> (Self, &'static str) {
        match self {
            Self::En => (Self::Ru, "Русский"),
            Self::Ru => (Self::En, "English"),
        }
    }

    pub(crate) const fn text(self) -> &'static Text {
        match self {
            Self::En => &EN,
            Self::Ru => &RU,
        }
    }
}

pub(crate) struct Text {
    pub(crate) not_found: &'static str,
    pub(crate) bad_request: &'static str,
    pub(crate) server_error: &'static str,
    pub(crate) busy: &'static str,
    pub(crate) home: &'static str,
    pub(crate) form_expired: &'static str,
    pub(crate) too_many_attempts: &'static str,
    pub(crate) sign_in_title: &'static str,
    pub(crate) username: &'static str,
    pub(crate) password: &'static str,
    pub(crate) sign_in: &'static str,
    pub(crate) wrong_credentials: &'static str,
    pub(crate) code_title: &'static str,
    pub(crate) code_hint: &'static str,
    pub(crate) code: &'static str,
    pub(crate) confirm: &'static str,
    pub(crate) wrong_code: &'static str,
    pub(crate) use_recovery_code: &'static str,
    pub(crate) recovery_title: &'static str,
    pub(crate) recovery_hint: &'static str,
    pub(crate) sign_out: &'static str,
    pub(crate) account_title: &'static str,
    pub(crate) change: &'static str,
    pub(crate) two_factor: &'static str,
    pub(crate) on: &'static str,
    pub(crate) off: &'static str,
    pub(crate) current_password: &'static str,
    pub(crate) new_password: &'static str,
    pub(crate) repeat_password: &'static str,
    pub(crate) save: &'static str,
    pub(crate) password_changed: &'static str,
    pub(crate) passwords_differ: &'static str,
    pub(crate) password_too_short: &'static str,
    pub(crate) password_too_long: &'static str,
    pub(crate) password_too_common: &'static str,
    pub(crate) wrong_password: &'static str,
    pub(crate) scan_code: &'static str,
    pub(crate) enter_key_manually: &'static str,
    pub(crate) recovery_codes: &'static str,
    pub(crate) recovery_codes_left: &'static str,
    pub(crate) new_recovery_codes: &'static str,
    pub(crate) turn_off: &'static str,
    pub(crate) done: &'static str,
    pub(crate) admins_keep_two_factor: &'static str,
    pub(crate) setup_title: &'static str,
    pub(crate) display_name: &'static str,
    pub(crate) create: &'static str,
    pub(crate) username_note: &'static str,
    pub(crate) username_invalid: &'static str,
    pub(crate) name_required: &'static str,
    pub(crate) set_password_title: &'static str,
    pub(crate) link_expired: &'static str,
    pub(crate) password_set: &'static str,
    pub(crate) consent_title: &'static str,
    pub(crate) scope_openid: &'static str,
    pub(crate) scope_profile: &'static str,
    pub(crate) scope_email: &'static str,
    pub(crate) scope_groups: &'static str,
    pub(crate) scope_offline_access: &'static str,
    pub(crate) allow: &'static str,
    pub(crate) deny: &'static str,
    pub(crate) switch_account: &'static str,
    pub(crate) no_access: &'static str,
    pub(crate) request_expired: &'static str,
    pub(crate) sign_in_to: &'static str,
    pub(crate) sign_out_confirm: &'static str,
    pub(crate) signed_out: &'static str,
}

static EN: Text = Text {
    not_found: "Page not found",
    bad_request: "This link doesn't work",
    server_error: "Something went wrong",
    busy: "The server is busy. Try again in a minute.",
    home: "Home",
    form_expired: "The page has expired. Try again.",
    too_many_attempts: "Too many attempts. Try again later.",
    sign_in_title: "Sign in",
    username: "Username",
    password: "Password",
    sign_in: "Sign in",
    wrong_credentials: "Wrong username or password",
    code_title: "Confirmation code",
    code_hint: "From your authenticator app",
    code: "Code",
    confirm: "Confirm",
    wrong_code: "Wrong code",
    use_recovery_code: "Use a recovery code",
    recovery_title: "Recovery code",
    recovery_hint: "Each code works once",
    sign_out: "Sign out",
    account_title: "Account",
    change: "Change",
    two_factor: "Two-factor sign-in",
    on: "On",
    off: "Off",
    current_password: "Current password",
    new_password: "New password",
    repeat_password: "Repeat the password",
    save: "Save",
    password_changed: "Password changed. Other sessions were signed out.",
    passwords_differ: "The passwords don't match",
    password_too_short: "Use at least 12 characters",
    password_too_long: "Use at most 256 characters",
    password_too_common: "This password is too easy to guess",
    wrong_password: "Wrong password",
    scan_code: "Scan the code with your authenticator app",
    enter_key_manually: "Enter the key manually",
    recovery_codes: "Recovery codes",
    recovery_codes_left: "Recovery codes left",
    new_recovery_codes: "New recovery codes",
    turn_off: "Turn off",
    done: "Done",
    admins_keep_two_factor: "Administrators can't turn it off",
    setup_title: "First administrator",
    display_name: "Name",
    create: "Create",
    username_note: "Lowercase letters, digits, dots and dashes",
    username_invalid: "Use lowercase letters, digits, dots and dashes",
    name_required: "Enter a name of up to 100 characters",
    set_password_title: "New password",
    link_expired: "This link has expired or was already used",
    password_set: "Password set",
    consent_title: "Access for",
    scope_openid: "Sign in with your account",
    scope_profile: "Name and username",
    scope_email: "Email address",
    scope_groups: "Groups",
    scope_offline_access: "Access while you're signed in",
    allow: "Allow",
    deny: "Deny",
    switch_account: "Use another account",
    no_access: "No access to",
    request_expired: "This sign-in request has expired. Start again from the application.",
    sign_in_to: "to",
    sign_out_confirm: "Sign out?",
    signed_out: "You're signed out",
};

static RU: Text = Text {
    not_found: "Страница не найдена",
    bad_request: "Ссылка не работает",
    server_error: "Что-то пошло не так",
    busy: "Сервер занят. Попробуйте через минуту.",
    home: "На главную",
    form_expired: "Страница устарела. Попробуйте ещё раз.",
    too_many_attempts: "Слишком много попыток. Попробуйте позже.",
    sign_in_title: "Вход",
    username: "Имя пользователя",
    password: "Пароль",
    sign_in: "Войти",
    wrong_credentials: "Неверное имя пользователя или пароль",
    code_title: "Код подтверждения",
    code_hint: "Из приложения-аутентификатора",
    code: "Код",
    confirm: "Подтвердить",
    wrong_code: "Неверный код",
    use_recovery_code: "Ввести резервный код",
    recovery_title: "Резервный код",
    recovery_hint: "Каждый код работает один раз",
    sign_out: "Выйти",
    account_title: "Аккаунт",
    change: "Изменить",
    two_factor: "Двухфакторный вход",
    on: "Включён",
    off: "Выключен",
    current_password: "Текущий пароль",
    new_password: "Новый пароль",
    repeat_password: "Повторите пароль",
    save: "Сохранить",
    password_changed: "Пароль изменён. Остальные сеансы завершены.",
    passwords_differ: "Пароли не совпадают",
    password_too_short: "Не короче 12 символов",
    password_too_long: "Не длиннее 256 символов",
    password_too_common: "Этот пароль слишком легко угадать",
    wrong_password: "Неверный пароль",
    scan_code: "Отсканируйте код в приложении-аутентификаторе",
    enter_key_manually: "Ввести ключ вручную",
    recovery_codes: "Резервные коды",
    recovery_codes_left: "Осталось резервных кодов",
    new_recovery_codes: "Новые резервные коды",
    turn_off: "Выключить",
    done: "Готово",
    admins_keep_two_factor: "Администраторам выключить нельзя",
    setup_title: "Первый администратор",
    display_name: "Имя",
    create: "Создать",
    username_note: "Строчные латинские буквы, цифры, точки и дефисы",
    username_invalid: "Только строчные латинские буквы, цифры, точки и дефисы",
    name_required: "Введите имя до 100 символов",
    set_password_title: "Новый пароль",
    link_expired: "Ссылка устарела или уже использована",
    password_set: "Пароль установлен",
    consent_title: "Доступ для",
    scope_openid: "Вход с вашим аккаунтом",
    scope_profile: "Имя и логин",
    scope_email: "Адрес почты",
    scope_groups: "Группы",
    scope_offline_access: "Доступ, пока вы в системе",
    allow: "Разрешить",
    deny: "Отклонить",
    switch_account: "Сменить аккаунт",
    no_access: "Нет доступа к",
    request_expired: "Запрос на вход устарел. Начните заново из приложения.",
    sign_in_to: "в",
    sign_out_confirm: "Выйти?",
    signed_out: "Вы вышли",
};
