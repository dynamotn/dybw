//! The caller policy through the agent: what each class of caller gets, remembered grants, the peer check around
//! the reply, one question at a time, and `dybw policy`. The scripted host plays the pinentry; the process table is
//! the fake one of `agent::testing::rig`.
#![expect(clippy::unwrap_used, clippy::indexing_slicing, reason = "tests")]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use dybw_proto::{AgentError, Field, Op, PolicyAction, PolicyEntry, PolicyRule, Reply, Select};
use serde_json::{Value, json};

use crate::agent::testing::{Rig, process, rig, rig_with, unlock};
use crate::caller::{At, Caller, Via, hash_of};
use crate::host::fake::Answer;
use crate::policy::Verdict;
use crate::read_tests::{VAULT, err, get_op, history_op, items, text, until};

const NOTE: &str = "n1";

async fn setup(edit: impl FnOnce(&mut Value)) -> (tempfile::TempDir, Rig) {
    let dir = tempfile::tempdir().unwrap();
    let rig = rig(dir.path());
    let mut vault: Value = serde_json::from_str(VAULT).unwrap();
    vault["ciphers"].as_array_mut().unwrap().iter_mut().for_each(|c| c["reprompt"] = json!(0));
    edit(&mut vault);
    rig.host.vault(&vault.to_string());
    unlock(&rig.agent, &rig.host, "work").await;
    (dir, rig)
}

fn policy_file(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join(".local/state/dybw/profiles/work/policy.json")
}

/// bash running `script`, always the same process: a grant for it lasts for that process.
fn tool(script: &str, hash: &str) -> Caller {
    Caller::Invoker {
        exe: "/bin/bash".into(),
        script: Some(script.into()),
        hash: hash.into(),
        relative: false,
        at: At::default(),
    }
}

/// A plain program: a grant for it is kept in `policy.json`.
fn program(exe: &str, hash: &str) -> Caller {
    Caller::Invoker { exe: exe.into(), script: None, hash: hash.into(), relative: false, at: At::default() }
}

fn ai() -> Caller {
    Caller::Ai { harness: "claude".into(), via: Via::Ancestry }
}

fn unknown() -> Caller {
    Caller::Unknown { why: "orphan".into(), peer: None }
}

fn bare_shell() -> Caller {
    Caller::Invoker { exe: "/bin/bash".into(), script: None, hash: "h".into(), relative: false, at: At::default() }
}

fn relative_script() -> Caller {
    let at = At::default();
    Caller::Invoker { exe: "/bin/bash".into(), script: Some("run.sh".into()), hash: "h".into(), relative: true, at }
}

fn password(rig: &Rig, caller: Caller) -> impl Future<Output = Reply> + use<> {
    let agent = rig.agent.clone();
    async move { agent.dispatch_as(get_op(NOTE, Select::Password), caller).await }
}

fn policy_op(action: PolicyAction) -> Op {
    Op::Policy { profile: Some("work".into()), action }
}

fn verdicts(rig: &Rig) -> Vec<Verdict> {
    rig.audit.events().iter().map(|e| e.verdict).collect()
}

fn entries(reply: Reply) -> Vec<PolicyEntry> {
    match reply {
        Reply::Policy { entries } => entries,
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn an_ai_class_caller_gets_no_value_and_no_question_but_still_lists() {
    let (_dir, rig) = setup(|_| {}).await;
    let agent = &rig.agent;
    for select in [Select::Password, Select::Field("user".into()), Select::Full, Select::Raw] {
        rig.host.allow();
        assert_eq!(agent.dispatch_as(get_op(NOTE, select), ai()).await, err(AgentError::Denied));
    }
    rig.host.allow();
    assert_eq!(agent.dispatch_as(history_op(NOTE), ai()).await, err(AgentError::Denied));
    assert!(rig.host.world().confirmed.is_empty(), "nobody is asked on behalf of an AI agent");
    assert_eq!(agent.opens("work").await, 0);
    assert_eq!(verdicts(&rig), vec![Verdict::Denied; 5]);
    // Refused before the vault is opened, so there is no item to name.
    assert!(rig.audit.events().iter().all(|e| e.item.is_none() && matches!(e.caller, Caller::Ai { .. })));
    // Names are for every class.
    let list = Op::List { profile: Some("work".into()), fields: vec![Field::Name], folder: None };
    let search =
        Op::Search { profile: Some("work".into()), term: "mail".into(), folder: None, fields: vec![Field::Name] };
    assert!(!items(agent.dispatch_as(list, ai()).await).is_empty());
    assert!(!items(agent.dispatch_as(search, ai()).await).is_empty());
    let status = agent.dispatch_as(Op::Status { profile: Some("work".into()) }, ai()).await;
    assert!(format!("{status:?}").contains("unlocked: true"));
    // Field names are names (ADR 0012): no question, no open, and the answer is audited with the item.
    let names = agent.dispatch_as(get_op("c1", Select::ListFields), ai()).await;
    assert!(matches!(names, Reply::FieldNames { names } if names.len() == 5));
    assert!(rig.host.world().confirmed.is_empty());
    assert_eq!(agent.opens("work").await, 0);
    let last = rig.audit.events().last().cloned().unwrap();
    assert_eq!(
        (last.op, last.kind, last.item.as_deref(), last.verdict),
        ("get", Some("list-fields"), Some("c1"), Verdict::Listed)
    );
}

#[tokio::test]
async fn the_field_names_of_a_reprompt_item_need_the_master_password_never_asked_for_an_ai_or_unknown_caller() {
    let (_dir, rig) = setup(|v| {
        v["ciphers"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .filter(|c| c["id"] == "c1")
            .for_each(|c| c["reprompt"] = json!(1));
    })
    .await;
    let agent = &rig.agent;
    let asked = rig.host.world().asked.len();
    assert_eq!(agent.dispatch_as(get_op("c1", Select::ListFields), ai()).await, err(AgentError::Denied));
    assert_eq!(agent.dispatch_as(get_op("c1", Select::ListFields), unknown()).await, err(AgentError::Denied));
    assert_eq!(rig.host.world().asked.len(), asked, "no prompt on behalf of an AI agent or an unidentified caller");
    assert_eq!(verdicts(&rig), [Verdict::Denied, Verdict::Denied]);
    // An invoker is asked for it (here: no answer), and gets nothing without it.
    assert_eq!(
        agent.dispatch_as(get_op("c1", Select::ListFields), tool("/opt/a.sh", "h1")).await,
        err(AgentError::Denied)
    );
    assert_eq!(rig.host.world().asked.len(), asked + 1);
    assert!(rig.host.world().confirmed.is_empty(), "the names need no confirmation, only the reprompt");
    assert_eq!(agent.opens("work").await, 0);
}

#[tokio::test]
async fn an_ai_request_for_a_value_never_unlocks_a_locked_profile() {
    let (_dir, rig) = setup(|_| {}).await;
    let agent = &rig.agent;
    assert_eq!(agent.dispatch(Op::Lock { target: dybw_proto::Target::Profile("work".into()) }).await, Reply::Done);
    let asked = rig.host.world().asked.len();
    rig.host.allow();
    assert_eq!(agent.dispatch_as(get_op(NOTE, Select::Password), ai()).await, err(AgentError::Denied));
    assert_eq!(rig.host.world().asked.len(), asked, "no master-password prompt on behalf of an AI agent");
    assert_eq!(verdicts(&rig), [Verdict::Denied]);
}

#[tokio::test]
async fn an_unknown_caller_is_asked_every_time_with_a_warning_and_never_remembered() {
    let (dir, rig) = setup(|_| {}).await;
    for _ in 0..2 {
        rig.host.allow_always();
        assert_eq!(text(password(&rig, unknown()).await), "the note's text");
    }
    let w = rig.host.world();
    assert_eq!(w.confirmed.len(), 2, "asked every time");
    assert!(w.confirmed[0].contains("detached or unknown caller — possibly an AI agent"), "{}", w.confirmed[0]);
    assert_eq!(w.offered, [false, false], "always is not even offered");
    drop(w);
    assert!(!policy_file(&dir).exists());
    assert_eq!(verdicts(&rig), [Verdict::Confirmed, Verdict::Confirmed]);
}

#[tokio::test]
async fn an_always_is_remembered_for_that_program_until_its_content_changes() {
    let (dir, rig) = setup(|_| {}).await;
    let a = || program("/usr/local/bin/mytool", "h1");
    rig.host.allow_always();
    assert_eq!(text(password(&rig, a()).await), "the note's text");
    assert_eq!(rig.host.world().offered, [true]);
    let stored: Value = serde_json::from_slice(&std::fs::read(policy_file(&dir)).unwrap()).unwrap();
    assert_eq!(stored["entries"][0]["hash"], "h1");
    assert_eq!(stored["entries"][0]["detached"], false);
    assert_eq!(std::fs::metadata(policy_file(&dir)).unwrap().permissions().mode() & 0o777, 0o600);

    // The same program is let through without a question, for any single value.
    assert_eq!(text(password(&rig, a()).await), "the note's text");
    assert_eq!(text(rig.agent.dispatch_as(get_op(NOTE, Select::Field("notes".into())), a()).await), "the note's text");
    assert_eq!(rig.host.world().confirmed.len(), 1, "no second question");

    // The program was replaced: the grant is revoked, and the question comes back.
    rig.host.allow();
    assert_eq!(text(password(&rig, program("/usr/local/bin/mytool", "h2")).await), "the note's text");
    assert_eq!(rig.host.world().confirmed.len(), 2);
    // Another program is another invoker.
    rig.host.allow();
    password(&rig, program("/usr/local/bin/other", "h1")).await;
    assert_eq!(rig.host.world().confirmed.len(), 3);
    // What was granted for the old content still names only that content.
    assert_eq!(text(password(&rig, a()).await), "the note's text");
    assert_eq!(rig.host.world().confirmed.len(), 3);
    assert_eq!(
        verdicts(&rig),
        [
            Verdict::Remembered,
            Verdict::Granted,
            Verdict::Granted,
            Verdict::Confirmed,
            Verdict::Confirmed,
            Verdict::Granted
        ]
    );
}

#[tokio::test]
async fn a_caller_that_cannot_be_named_stably_is_never_offered_always() {
    let (dir, rig) = setup(|_| {}).await;
    for caller in [relative_script(), bare_shell()] {
        for _ in 0..2 {
            rig.host.allow_always();
            assert_eq!(text(password(&rig, caller.clone()).await), "the note's text");
        }
    }
    assert_eq!(rig.host.world().offered, [false; 4]);
    assert_eq!(rig.host.world().confirmed.len(), 4, "asked every time");
    assert!(!policy_file(&dir).exists());
}

#[tokio::test]
async fn a_grant_never_satisfies_a_reprompt() {
    let (_dir, rig) = setup(|v| {
        for c in v["ciphers"].as_array_mut().unwrap() {
            if c["id"] == "c1" {
                c["reprompt"] = json!(1);
            }
        }
    })
    .await;
    rig.host.allow_always();
    assert_eq!(text(password(&rig, tool("/opt/a.sh", "h1")).await), "the note's text");
    let before = rig.host.world().confirmed.len();
    let opens = rig.agent.opens("work").await;
    // The grant answers the policy, never the reprompt: without the master password, nothing is opened.
    let reply = rig.agent.dispatch_as(get_op("c1", Select::Password), tool("/opt/a.sh", "h1")).await;
    assert_eq!(reply, err(AgentError::Denied));
    assert_eq!(rig.host.world().confirmed.len(), before, "the grant answered the policy");
    assert_eq!(rig.host.world().prompts.last().unwrap(), "Master password:");
    assert_eq!(rig.agent.opens("work").await, opens, "not opened");
    rig.host.answer(Answer::Text(crate::host::fake::PASSWORD));
    let reply = rig.agent.dispatch_as(get_op("c1", Select::Password), tool("/opt/a.sh", "h1")).await;
    assert_eq!(text(reply), "pw-ünï-😀");
    assert_eq!(verdicts(&rig)[1..], [Verdict::Granted, Verdict::Declined, Verdict::Granted, Verdict::Reprompted]);
}

#[tokio::test]
async fn a_policy_file_that_cannot_be_trusted_never_allows() {
    let (dir, rig) = setup(|_| {}).await;
    let mine = || program("/usr/local/bin/mytool", "h1");
    rig.host.allow_always();
    password(&rig, mine()).await;
    let file = policy_file(&dir);
    // Anyone could have written a file others can read.
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    rig.host.allow();
    password(&rig, mine()).await;
    assert_eq!(rig.host.world().confirmed.len(), 2, "asked again");
    // So can a link, and text that is not a policy.
    std::fs::remove_file(&file).unwrap();
    std::os::unix::fs::symlink("/dev/null", &file).unwrap();
    rig.host.allow();
    password(&rig, mine()).await;
    std::fs::remove_file(&file).unwrap();
    std::fs::write(&file, "allow everything").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    rig.host.allow();
    password(&rig, mine()).await;
    assert_eq!(rig.host.world().confirmed.len(), 4);
}

#[tokio::test]
async fn a_grant_that_cannot_be_written_still_serves_this_request_once() {
    let (dir, rig) = setup(|_| {}).await;
    std::fs::create_dir(policy_file(&dir)).unwrap();
    rig.host.allow_always();
    assert_eq!(text(password(&rig, program("/usr/local/bin/mytool", "h1")).await), "the note's text");
    assert_eq!(verdicts(&rig), [Verdict::Confirmed]);
}

#[tokio::test]
async fn a_peer_that_changes_before_or_while_the_user_is_asked_gets_nothing() {
    let (_dir, rig) = setup(|_| {}).await;
    // Replaced before the request is served: refused, and no question about a program that is gone.
    rig.tree.add(100, process(101));
    assert_eq!(password(&rig, tool("/opt/a.sh", "h1")).await, err(AgentError::Denied));
    assert!(rig.host.world().confirmed.is_empty());
    let event = &rig.audit.events()[0];
    assert_eq!((event.op, event.verdict, event.profile.as_str()), ("get", Verdict::Denied, "work"));
    assert_eq!(event.kind, Some("password"));
    // Names are not held to it.
    let list = Op::List { profile: Some("work".into()), fields: vec![Field::Name], folder: None };
    assert!(!items(rig.agent.dispatch_as(list, tool("/opt/a.sh", "h1")).await).is_empty());

    // Replaced after the user said yes, before the reply: the value is not delivered.
    rig.tree.add(100, process(100));
    rig.host.world().confirms.push_back(Answer::Held);
    let pending = tokio::spawn(password(&rig, tool("/opt/a.sh", "h1")));
    until(|| rig.host.world().confirmed.len() == 1).await;
    rig.tree.add(100, process(102));
    rig.host.world().release.notify_one();
    assert_eq!(pending.await.unwrap(), err(AgentError::Denied));
    assert_eq!(rig.agent.opens("work").await, 0, "nothing was opened for the changed peer");
    assert_eq!(verdicts(&rig), [Verdict::Denied, Verdict::Confirmed, Verdict::Denied]);
}

#[tokio::test]
async fn a_policy_change_is_dropped_when_the_peer_changes_while_the_user_is_asked() {
    let (dir, rig) = setup(|_| {}).await;
    rig.host.world().confirms.push_back(Answer::Held);
    let deny = PolicyAction::Deny { invoker: "/usr/bin/x".into(), script: None };
    let agent = rig.agent.clone();
    let pending = tokio::spawn(async move { agent.dispatch(policy_op(deny)).await });
    until(|| rig.host.world().confirmed.len() == 1).await;
    rig.tree.add(100, process(103));
    rig.host.world().release.notify_one();
    assert_eq!(pending.await.unwrap(), err(AgentError::Denied));
    assert!(!policy_file(&dir).exists());
    assert_eq!(verdicts(&rig), [Verdict::Denied]);
}

#[tokio::test]
async fn an_allow_that_could_never_match_is_refused_and_a_deny_of_it_is_not() {
    let (dir, rig) = setup(|_| {}).await;
    let script = std::fs::canonicalize(dir.path().join("config.toml")).unwrap().to_string_lossy().into_owned();
    // The invoker is stored resolved: /bin is a symlink to /usr/bin on Linux.
    let bash = std::fs::canonicalize("/bin/bash").unwrap().to_string_lossy().into_owned();
    let allow = |invoker: &str, script: Option<&str>| PolicyAction::Allow {
        invoker: invoker.into(),
        script: script.map(Into::into),
        detached: false,
    };
    // A shell, with or without a script (its grants last for a process), and a launcher (it runs anything).
    for refused in [allow("/bin/bash", None), allow("/bin/bash", Some(&script)), allow("/usr/bin/xargs", None)] {
        assert_eq!(rig.agent.dispatch(policy_op(refused)).await, err(AgentError::Config));
    }
    assert!(rig.host.world().confirmed.is_empty(), "not even asked");
    rig.host.allow();
    let deny = PolicyAction::Deny { invoker: "/bin/bash".into(), script: None };
    assert_eq!(rig.agent.dispatch(policy_op(deny)).await, Reply::Done);
    rig.host.allow();
    let deny = PolicyAction::Deny { invoker: "/bin/bash".into(), script: Some(script.clone()) };
    assert_eq!(rig.agent.dispatch(policy_op(deny)).await, Reply::Done);
    let asked = rig.host.world().confirmed[1].clone();
    assert!(asked.contains(&format!("always refuse reading values for {bash} running {script}")), "{asked}");
}

#[tokio::test]
async fn a_request_for_another_invoker_waits_for_the_screen_and_gets_its_own_question() {
    let (_dir, rig) = setup(|_| {}).await;
    rig.host.world().confirms.push_back(Answer::Held);
    let first = tokio::spawn(password(&rig, tool("/opt/a.sh", "h1")));
    until(|| rig.host.world().confirmed.len() == 1).await;
    // B comes in while A's question is open, and the user will say no to it.
    let second = tokio::spawn(password(&rig, tool("/opt/b.sh", "h9")));
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert_eq!(rig.host.world().confirmed.len(), 1, "one question on the screen at a time");
    rig.host.world().release.notify_one();
    assert_eq!(text(first.await.unwrap()), "the note's text");
    // A's yes is not B's: B has a question of its own, which names B.
    assert_eq!(second.await.unwrap(), err(AgentError::Denied));
    let w = rig.host.world();
    assert_eq!(w.confirmed.len(), 2);
    assert!(w.confirmed[0].contains("/opt/a.sh") && !w.confirmed[0].contains("/opt/b.sh"));
    assert!(w.confirmed[1].contains("/opt/b.sh") && !w.confirmed[1].contains("/opt/a.sh"));
}

#[tokio::test]
async fn a_request_of_the_same_invoker_that_waited_finds_the_grant_made_meanwhile() {
    let (_dir, rig) = setup(|_| {}).await;
    rig.host.world().confirms.push_back(Answer::HeldAlways);
    let first = tokio::spawn(password(&rig, tool("/opt/a.sh", "h1")));
    until(|| rig.host.world().confirmed.len() == 1).await;
    let second = tokio::spawn(password(&rig, tool("/opt/a.sh", "h1")));
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    rig.host.world().release.notify_one();
    assert_eq!(text(first.await.unwrap()), "the note's text");
    assert_eq!(text(second.await.unwrap()), "the note's text");
    assert_eq!(rig.host.world().confirmed.len(), 1, "the second was not asked again");
    assert_eq!(verdicts(&rig), [Verdict::Remembered, Verdict::Granted]);
}

#[tokio::test]
async fn policy_show_is_open_to_every_class_but_ai_and_changes_need_a_named_invoker() {
    let (dir, rig) = setup(|_| {}).await;
    let agent = &rig.agent;
    for caller in [unknown(), tool("/opt/a.sh", "h1")] {
        assert!(entries(agent.dispatch_as(policy_op(PolicyAction::Show), caller).await).is_empty());
    }
    let changes = [
        PolicyAction::Allow { invoker: "/usr/bin/x".into(), script: None, detached: false },
        PolicyAction::Deny { invoker: "/usr/bin/x".into(), script: None },
        PolicyAction::Forget { invoker: "/usr/bin/x".into() },
    ];
    for caller in [ai(), unknown()] {
        for change in &changes {
            rig.host.allow();
            assert_eq!(agent.dispatch_as(policy_op(change.clone()), caller.clone()).await, err(AgentError::Denied));
        }
    }
    assert!(rig.host.world().confirmed.is_empty(), "no question is put for them");
    assert_eq!(verdicts(&rig), vec![Verdict::Denied; 6]);
    assert_eq!(rig.audit.events()[0].op, "policy-allow");
    assert!(!policy_file(&dir).exists());
}

#[tokio::test]
async fn allow_deny_and_forget_ask_the_user_and_change_what_the_next_request_gets() {
    let (dir, rig) = setup(|_| {}).await;
    let exe = dir.path().join("mytool");
    std::fs::write(&exe, "elf v1").unwrap();
    let exe = std::fs::canonicalize(exe).unwrap();
    let path = exe.to_string_lossy().into_owned();
    let hash = hash_of(&exe).unwrap();
    let allow = |detached| PolicyAction::Allow { invoker: path.clone(), script: None, detached };
    let job = || program(&path, &hash);

    // The user says no: nothing changes.
    assert_eq!(rig.agent.dispatch(policy_op(allow(false))).await, err(AgentError::Denied));
    assert!(!policy_file(&dir).exists());
    // Yes: the program is let through from now on, without a question, as long as the file is what it was.
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(policy_op(allow(false))).await, Reply::Done);
    let shown = entries(rig.agent.dispatch(policy_op(PolicyAction::Show)).await);
    let want =
        PolicyEntry { exe: path.clone(), script: None, hash: hash.clone(), rule: PolicyRule::Allow, detached: false };
    assert_eq!(shown.as_slice(), std::slice::from_ref(&want));
    let asked = rig.host.world().confirmed.clone();
    assert!(asked[1].contains(&format!("always allow reading values for {path} (dybw policy)")), "{}", asked[1]);
    assert_eq!(text(password(&rig, job()).await), "the note's text");
    assert_eq!(rig.host.world().confirmed.len(), 2, "no question for the value");
    // A detached grant is a grant of its own, next to the other.
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(policy_op(allow(true))).await, Reply::Done);
    assert!(rig.host.world().confirmed[2].contains("when run detached (parent exited)"));
    let shown = entries(rig.agent.dispatch(policy_op(PolicyAction::Show)).await);
    assert_eq!(shown, [want.clone(), PolicyEntry { detached: true, ..want }]);
    std::fs::write(&exe, "elf v2").unwrap();
    rig.host.allow();
    password(&rig, program(&path, &hash_of(&exe).unwrap())).await;
    assert_eq!(rig.host.world().confirmed.len(), 4, "a replaced program is asked about again");

    // A deny is by path and holds whatever the content, for every script of the program too.
    rig.host.allow();
    let deny = PolicyAction::Deny { invoker: path.clone(), script: None };
    assert_eq!(rig.agent.dispatch(policy_op(deny)).await, Reply::Done);
    assert_eq!(password(&rig, job()).await, err(AgentError::Denied));
    assert_eq!(rig.host.world().confirmed.len(), 5, "refused without a question");
    assert!(rig.host.world().confirmed[4].contains("always refuse reading values for"));
    assert_eq!(entries(rig.agent.dispatch(policy_op(PolicyAction::Show)).await).len(), 1, "the deny replaced both");

    // Forget: the question comes back.
    rig.host.allow();
    let forget = PolicyAction::Forget { invoker: path.clone() };
    assert_eq!(rig.agent.dispatch(policy_op(forget)).await, Reply::Done);
    assert!(rig.host.world().confirmed[5].contains("forget what is remembered for"));
    assert!(entries(rig.agent.dispatch(policy_op(PolicyAction::Show)).await).is_empty());
    rig.host.allow();
    assert_eq!(text(password(&rig, job()).await), "the note's text");
    assert_eq!(
        rig.audit.events().iter().filter(|e| e.item.is_none()).map(|e| (e.op, e.verdict)).collect::<Vec<_>>(),
        [
            ("policy-allow", Verdict::Declined),
            ("policy-allow", Verdict::Confirmed),
            ("policy-allow", Verdict::Confirmed),
            ("policy-deny", Verdict::Confirmed),
            ("policy-forget", Verdict::Confirmed)
        ]
    );
}

#[tokio::test]
async fn a_policy_change_that_cannot_be_planned_or_saved_is_refused_after_no_question_or_says_so() {
    let (dir, rig) = setup(|_| {}).await;
    let agent = &rig.agent;
    let not_a_path = |action| async move { agent.dispatch(policy_op(action)).await };
    rig.host.allow();
    let relative = PolicyAction::Allow { invoker: "tool".into(), script: None, detached: false };
    assert_eq!(not_a_path(relative).await, err(AgentError::Config));
    let relative_script = PolicyAction::Deny { invoker: "/usr/bin/x".into(), script: Some("run.sh".into()) };
    assert_eq!(not_a_path(relative_script).await, err(AgentError::Config));
    let missing = PolicyAction::Allow { invoker: "/no/such/program".into(), script: None, detached: false };
    assert_eq!(not_a_path(missing).await, err(AgentError::Config));
    assert!(rig.host.world().confirmed.is_empty(), "nothing was asked about a change that cannot be made");
    // Forget takes a name that is not a path too (it only matches nothing).
    rig.host.allow();
    assert_eq!(not_a_path(PolicyAction::Forget { invoker: "tool".into() }).await, Reply::Done);
    // The file cannot be written.
    std::fs::create_dir(policy_file(&dir)).unwrap();
    rig.host.allow();
    let deny = PolicyAction::Deny { invoker: "/usr/bin/x".into(), script: None };
    assert_eq!(not_a_path(deny).await, err(AgentError::Internal));
    assert_eq!(rig.audit.events().last().unwrap().verdict, Verdict::Failed, "the real outcome is recorded");
}

#[tokio::test]
async fn a_policy_change_waits_for_a_peer_that_is_still_the_one_that_asked() {
    let (dir, rig) = setup(|_| {}).await;
    rig.tree.add(100, process(101));
    rig.host.allow();
    let deny = PolicyAction::Deny { invoker: "/usr/bin/x".into(), script: None };
    assert_eq!(rig.agent.dispatch(policy_op(deny)).await, err(AgentError::Denied));
    assert!(rig.host.world().confirmed.is_empty() && !policy_file(&dir).exists());
}

#[tokio::test]
async fn a_request_over_a_socket_is_resolved_at_accept_and_an_orphan_is_asked_about() {
    use dybw_proto::{Request, decode_response, encode};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (_dir, rig) = setup(|_| {}).await;
    let (mut client, server) = tokio::net::UnixStream::pair().unwrap();
    // The process table knows the test process (its real start and image) as a `dybw` with no parent: an orphan.
    let me = dybw_peer::peer_of_stream(&client).unwrap();
    let mut proc = process(me.token.start);
    proc.image = me.token.image.clone();
    rig.tree.add(me.pid, proc);
    let task = tokio::spawn(crate::server::handle(Arc::clone(&rig.agent), server));
    rig.host.allow_always();
    client.write_all(&encode(&Request::new(get_op(NOTE, Select::Password))).unwrap()).await.unwrap();
    let mut out = Vec::new();
    client.read_to_end(&mut out).await.unwrap();
    assert!(!task.await.unwrap());
    let reply = decode_response(&out).unwrap().unwrap().0.reply;
    assert_eq!(text(reply), "the note's text");
    assert!(rig.host.world().confirmed[0].contains("detached or unknown caller"));
    assert!(matches!(rig.audit.events()[0].caller, Caller::Unknown { .. }));
}

/// A process table that stops vouching for the peer after `n` questions about it.
struct Flips(Arc<dybw_peer::Fake>, std::sync::atomic::AtomicUsize, usize);

impl dybw_peer::ProcessSource for Flips {
    fn peer_of(&self, sock: std::os::fd::BorrowedFd<'_>) -> Result<dybw_peer::Peer, dybw_peer::Error> {
        self.0.peer_of(sock)
    }
    fn process(&self, pid: u32) -> Result<dybw_peer::Process, dybw_peer::Error> {
        self.0.process(pid)
    }
    fn still_same(&self, peer: &dybw_peer::Peer) -> bool {
        self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < self.2 && self.0.still_same(peer)
    }
    fn executable(&self, pid: u32, exe: &std::path::Path) -> std::io::Result<std::fs::File> {
        self.0.executable(pid, exe)
    }
}

#[tokio::test]
async fn a_peer_that_goes_after_the_worker_opened_the_item_still_gets_no_value() {
    let dir = tempfile::tempdir().unwrap();
    // Three checks of a get: before the request, after the answer (worker), and before the reply is written.
    let rig = rig_with(dir.path(), |tree| Arc::new(Flips(tree, Default::default(), 2)));
    let mut vault: Value = serde_json::from_str(VAULT).unwrap();
    vault["ciphers"].as_array_mut().unwrap().iter_mut().for_each(|c| c["reprompt"] = json!(0));
    rig.host.vault(&vault.to_string());
    unlock(&rig.agent, &rig.host, "work").await;
    rig.host.allow();
    assert_eq!(password(&rig, tool("/opt/a.sh", "h1")).await, err(AgentError::Denied));
    assert_eq!(rig.agent.opens("work").await, 1, "it was opened, and the reply was withheld");
    assert_eq!(verdicts(&rig), [Verdict::Confirmed, Verdict::Denied]);
}

#[tokio::test]
async fn a_peer_that_goes_after_the_code_was_made_gets_no_code() {
    let dir = tempfile::tempdir().unwrap();
    let rig = rig_with(dir.path(), |tree| Arc::new(Flips(tree, Default::default(), 2)));
    let mut vault: Value = serde_json::from_str(VAULT).unwrap();
    vault["ciphers"].as_array_mut().unwrap().iter_mut().for_each(|c| c["reprompt"] = json!(0));
    rig.host.vault(&vault.to_string());
    unlock(&rig.agent, &rig.host, "work").await;
    rig.host.allow();
    let code = Op::Code {
        profile: Some("work".into()),
        needle: "c1".into(),
        user: None,
        folder: None,
        ignorecase: false,
        next: false,
    };
    assert_eq!(rig.agent.dispatch_as(code, tool("/opt/a.sh", "h1")).await, err(AgentError::Denied));
    assert_eq!(rig.agent.opens("work").await, 1, "the key was opened, and the code withheld");
    assert_eq!(verdicts(&rig), [Verdict::Confirmed, Verdict::Denied]);
}

#[tokio::test]
async fn every_read_of_an_ai_or_unknown_caller_is_logged_also_when_it_never_reaches_a_decision() {
    let (_dir, rig) = setup(|_| {}).await;
    let agent = &rig.agent;
    let list = || Op::List { profile: Some("work".into()), fields: vec![Field::Name], folder: None };
    let search =
        || Op::Search { profile: Some("work".into()), term: "mail".into(), folder: None, fields: vec![Field::Name] };
    for caller in [ai(), unknown()] {
        items(agent.dispatch_as(list(), caller.clone()).await);
        items(agent.dispatch_as(search(), caller.clone()).await);
        // No such item: an AI caller is refused up front, an unknown one fails before any decision; the needle is
        // nowhere in the line.
        let missing = agent.dispatch_as(get_op("no-such-item", Select::Full), caller.clone()).await;
        assert!(matches!(missing, Reply::Error { .. }));
        let missing = agent.dispatch_as(history_op("no-such-item"), caller).await;
        assert!(matches!(missing, Reply::Error { .. }));
    }
    let events = rig.audit.events();
    let want = |miss| [Verdict::Listed, Verdict::Listed, miss, miss];
    assert_eq!(verdicts(&rig), [want(Verdict::Denied), want(Verdict::Failed)].concat());
    let ops: Vec<_> = events.iter().take(4).map(|e| (e.op, e.kind)).collect();
    assert_eq!(ops, [("list", None), ("search", None), ("get", Some("full")), ("history", None)]);
    assert!(events.iter().all(|e| e.item.is_none() && e.profile == "work"));
    // An invoker's names-only requests are not logged; a decision on its value is, as before.
    items(agent.dispatch_as(list(), tool("/opt/a.sh", "h1")).await);
    assert_eq!(events.len(), rig.audit.events().len());
}

#[tokio::test]
async fn an_ai_class_caller_cannot_stop_unlock_log_in_or_touch_the_policy() {
    let (_dir, rig) = setup(|_| {}).await;
    let agent = &rig.agent;
    let asked = rig.host.world().asked.len();
    let work = || Some("work".to_owned());
    for op in [
        Op::StopAgent,
        Op::Unlock { profile: work() },
        Op::Login { profile: work() },
        policy_op(PolicyAction::Show),
        policy_op(PolicyAction::Forget { invoker: "/usr/bin/x".into() }),
    ] {
        rig.host.allow();
        assert_eq!(agent.dispatch_as(op, ai()).await, err(AgentError::Denied));
    }
    assert_eq!(rig.host.world().asked.len(), asked, "no password or API-key prompt on behalf of an AI agent");
    assert!(rig.host.world().confirmed.is_empty());
    assert_eq!(verdicts(&rig), vec![Verdict::Denied; 5]);
    let ops: Vec<_> = rig.audit.events().iter().map(|e| e.op).collect();
    assert_eq!(ops, ["stop_agent", "unlock", "login", "policy-show", "policy-forget"]);
    // The others may still look at the policy.
    assert!(entries(agent.dispatch_as(policy_op(PolicyAction::Show), unknown()).await).is_empty());
}

#[tokio::test]
async fn an_ai_list_of_a_locked_profile_answers_locked_and_raises_no_prompt() {
    let (_dir, rig) = setup(|_| {}).await;
    let agent = &rig.agent;
    assert_eq!(agent.dispatch(Op::Lock { target: dybw_proto::Target::Profile("work".into()) }).await, Reply::Done);
    let asked = rig.host.world().asked.len();
    let list = || Op::List { profile: Some("work".into()), fields: vec![Field::Name], folder: None };
    let search =
        Op::Search { profile: Some("work".into()), term: "mail".into(), folder: None, fields: vec![Field::Name] };
    let sync = Op::Sync { target: dybw_proto::Target::Profile("work".into()) };
    for op in [list(), search, sync] {
        assert_eq!(agent.dispatch_as(op, ai()).await, err(AgentError::Locked));
    }
    assert_eq!(rig.host.world().asked.len(), asked, "an AI agent never raises the master-password prompt");
    // Anyone else still unlocks on first need.
    rig.host.answer(Answer::Text(crate::host::fake::PASSWORD));
    assert!(!items(agent.dispatch_as(list(), unknown()).await).is_empty());
}

#[tokio::test]
async fn a_deny_without_a_script_covers_every_script_of_that_program() {
    let (dir, rig) = setup(|_| {}).await;
    let entry = PolicyEntry {
        exe: "/bin/bash".into(),
        script: None,
        hash: String::new(),
        rule: PolicyRule::Deny,
        detached: false,
    };
    let file = serde_json::json!({ "version": 1, "entries": [entry] });
    std::fs::create_dir_all(policy_file(&dir).parent().unwrap()).unwrap();
    std::fs::write(policy_file(&dir), file.to_string()).unwrap();
    std::fs::set_permissions(policy_file(&dir), PermissionsExt::from_mode(0o600)).unwrap();
    rig.host.allow();
    assert_eq!(password(&rig, tool("/opt/a.sh", "h1")).await, err(AgentError::Denied));
    assert!(rig.host.world().confirmed.is_empty());
}

fn app() -> Caller {
    program("/usr/local/bin/app", "h")
}

#[tokio::test]
async fn a_grant_never_covers_the_whole_item_its_raw_json_or_the_history() {
    let (_dir, rig) = setup(|_| {}).await;
    rig.host.allow_always();
    assert_eq!(text(password(&rig, app()).await), "the note's text");
    for op in [get_op(NOTE, Select::Full), get_op(NOTE, Select::Raw), history_op(NOTE)] {
        rig.host.allow_always();
        assert!(!matches!(rig.agent.dispatch_as(op, app()).await, Reply::Error { .. }));
    }
    let w = rig.host.world();
    assert_eq!(w.confirmed.len(), 4, "asked for each, the grant notwithstanding");
    assert_eq!(w.offered, [true, false, false, false], "and never offered always");
}

fn bash_running(script: &str) -> Caller {
    tool(script, "h1")
}

#[tokio::test]
async fn an_always_for_a_script_lasts_for_that_process_only_and_is_never_written() {
    let (dir, rig) = setup(|_| {}).await;
    rig.host.allow_always();
    assert_eq!(text(password(&rig, bash_running("/opt/a.sh")).await), "the note's text");
    assert!(!policy_file(&dir).exists(), "a script's argv is its own to forge: nothing goes to disk");
    let asked = rig.host.world().confirmed[0].clone();
    assert!(asked.contains("claims to run /opt/a.sh") && asked.contains("[always (this process only)]"), "{asked}");
    // The same process again: granted, no question.
    // (Nothing is scripted: a question would be answered no.)
    assert_eq!(text(password(&rig, bash_running("/opt/a.sh")).await), "the note's text");
    assert_eq!(rig.host.world().confirmed.len(), 1);
}

#[tokio::test]
async fn a_stop_from_an_ai_agent_over_the_socket_is_refused_and_the_agent_keeps_running() {
    use dybw_proto::{Request, decode_response, encode};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (_dir, rig) = setup(|_| {}).await;
    let (mut client, server) = tokio::net::UnixStream::pair().unwrap();
    let me = dybw_peer::peer_of_stream(&client).unwrap();
    let mut proc = process(me.token.start);
    proc.image = me.token.image.clone();
    proc.env = Some(vec![("CLAUDECODE".into(), "1".into())]);
    rig.tree.add(me.pid, proc);
    let task = tokio::spawn(crate::server::handle(Arc::clone(&rig.agent), server));
    client.write_all(&encode(&Request::new(Op::StopAgent)).unwrap()).await.unwrap();
    let mut out = Vec::new();
    client.read_to_end(&mut out).await.unwrap();
    assert!(!task.await.unwrap(), "the agent must not stop");
    assert_eq!(decode_response(&out).unwrap().unwrap().0.reply, err(AgentError::Denied));
}

/// `caller` as another process, or with its parent gone.
fn moved(caller: Caller, pid: u32, detached: bool) -> Caller {
    let Caller::Invoker { exe, script, hash, relative, .. } = caller else { unreachable!() };
    Caller::Invoker { exe, script, hash, relative, at: At { pid, detached, ..At::default() } }
}

#[tokio::test]
async fn a_script_grant_is_for_one_process_dropped_by_a_lock_and_bounded() {
    let (_dir, rig) = setup(|_| {}).await;
    rig.host.allow_always();
    password(&rig, moved(tool("/opt/a.sh", "h1"), 1, false)).await;
    // Another process running the same script is asked; so is the first once its parent is gone.
    rig.host.allow();
    password(&rig, moved(tool("/opt/a.sh", "h1"), 2, false)).await;
    rig.host.allow();
    password(&rig, moved(tool("/opt/a.sh", "h1"), 1, true)).await;
    assert_eq!(rig.host.world().confirmed.len(), 3);
    assert!(rig.host.world().confirmed[2].contains("detached caller (parent exited) — possibly an AI agent"));
    assert_eq!(rig.host.world().offered, [true, true, false], "a detached caller is never offered always");
    // A lock forgets every per-process grant.
    assert_eq!(rig.agent.dispatch(Op::Lock { target: dybw_proto::Target::All }).await, Reply::Done);
    unlock(&rig.agent, &rig.host, "work").await;
    rig.host.allow();
    password(&rig, moved(tool("/opt/a.sh", "h1"), 1, false)).await;
    assert_eq!(rig.host.world().confirmed.len(), 4, "asked again after the lock");
    // At most 64 are held: the oldest goes first.
    for pid in 100..=164 {
        rig.host.allow_always();
        password(&rig, moved(tool("/opt/a.sh", "h1"), pid, false)).await;
    }
    let asked = rig.host.world().confirmed.len();
    password(&rig, moved(tool("/opt/a.sh", "h1"), 164, false)).await;
    assert_eq!(rig.host.world().confirmed.len(), asked, "the newest is held");
    rig.host.allow();
    password(&rig, moved(tool("/opt/a.sh", "h1"), 100, false)).await;
    assert_eq!(rig.host.world().confirmed.len(), asked + 1, "the oldest was dropped");
}

#[tokio::test]
async fn a_detached_program_is_never_offered_always_and_uses_only_a_detached_grant() {
    let (dir, rig) = setup(|_| {}).await;
    let loose = || moved(program("/usr/local/bin/mytool", "h1"), 0, true);
    rig.host.allow_always();
    assert_eq!(text(password(&rig, loose()).await), "the note's text");
    assert_eq!(rig.host.world().offered, [false]);
    assert!(!policy_file(&dir).exists());
    let entry = |detached| PolicyEntry {
        exe: "/usr/local/bin/mytool".into(),
        script: None,
        hash: "h1".into(),
        rule: PolicyRule::Allow,
        detached,
    };
    let write = |entries: &[PolicyEntry]| {
        std::fs::create_dir_all(policy_file(&dir).parent().unwrap()).unwrap();
        std::fs::write(policy_file(&dir), json!({ "version": 1, "entries": entries }).to_string()).unwrap();
        std::fs::set_permissions(policy_file(&dir), PermissionsExt::from_mode(0o600)).unwrap();
    };
    // A grant for the program run normally is not one for it run detached.
    write(&[entry(false)]);
    rig.host.allow();
    password(&rig, loose()).await;
    assert_eq!(rig.host.world().confirmed.len(), 2);
    write(&[entry(true)]);
    assert_eq!(text(password(&rig, loose()).await), "the note's text");
    assert_eq!(rig.host.world().confirmed.len(), 2, "the detached grant lets it through");
}

#[tokio::test]
async fn a_peer_that_goes_while_a_write_waits_its_turn_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    // Three checks of a remove: before the request, after the answers (worker), and once the write has its turn.
    let rig = rig_with(dir.path(), |tree| Arc::new(Flips(tree, Default::default(), 2)));
    let mut vault: Value = serde_json::from_str(VAULT).unwrap();
    vault["ciphers"].as_array_mut().unwrap().iter_mut().for_each(|c| c["reprompt"] = json!(0));
    rig.host.vault(&vault.to_string());
    unlock(&rig.agent, &rig.host, "work").await;
    rig.host.allow();
    let remove =
        Op::Remove { profile: Some("work".into()), needle: NOTE.into(), user: None, folder: None, ignorecase: false };
    assert_eq!(rig.agent.dispatch(remove).await, err(AgentError::Denied));
    assert_eq!(rig.host.world().count("/delete"), 0, "nothing was sent");
    assert_eq!(verdicts(&rig), [Verdict::Denied]);
}

#[tokio::test]
async fn a_peer_that_goes_while_the_user_is_asked_purges_nothing() {
    let dir = tempfile::tempdir().unwrap();
    // Two checks of a purge: before the request, and after the user's yes (worker).
    let rig = rig_with(dir.path(), |tree| Arc::new(Flips(tree, Default::default(), 1)));
    let mut vault: Value = serde_json::from_str(VAULT).unwrap();
    vault["ciphers"].as_array_mut().unwrap().iter_mut().for_each(|c| c["reprompt"] = json!(0));
    rig.host.vault(&vault.to_string());
    unlock(&rig.agent, &rig.host, "work").await;
    rig.host.allow();
    assert_eq!(rig.agent.dispatch(Op::Purge { profile: Some("work".into()) }).await, err(AgentError::Denied));
    assert!(dir.path().join(".cache/dybw/profiles/work/sync.json").exists(), "nothing was deleted");
    assert_eq!(rig.host.world().confirmed.len(), 1);
    assert_eq!(verdicts(&rig), [Verdict::Denied]);
}

#[tokio::test]
async fn an_rbw_item_is_not_handed_to_a_peer_that_went_after_it_was_opened() {
    let dir = tempfile::tempdir().unwrap();
    // Three checks of a value read: before the request, after the yes (worker), and before the reply is handed back.
    let rig = rig_with(dir.path(), |tree| Arc::new(Flips(tree, Default::default(), 2)));
    let mut vault: Value = serde_json::from_str(VAULT).unwrap();
    vault["ciphers"].as_array_mut().unwrap().iter_mut().for_each(|c| c["reprompt"] = json!(0));
    rig.host.vault(&vault.to_string());
    unlock(&rig.agent, &rig.host, "work").await;
    rig.host.allow();
    let Op::Get { profile, needle, user, folder, ignorecase, .. } = get_op(NOTE, Select::Raw) else { panic!() };
    let raw = Op::Get { profile, needle, user, folder, ignorecase, select: Select::Raw, rbw: true };
    assert_eq!(rig.agent.dispatch(raw).await, err(AgentError::Denied));
    assert_eq!(rig.agent.opens("work").await, 1, "opened, then held back");
}
