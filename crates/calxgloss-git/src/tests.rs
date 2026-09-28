use super::*;
use std::env;

fn temp_git_repo() -> (PathBuf, GitManager) {
    let thread = std::thread::current();
    let thread_name = thread.name().unwrap_or("unknown");
    let safe_name = thread_name.replace(|c: char| !c.is_alphanumeric(), "_");
    let tmp_dir = env::temp_dir().join(format!("calxgloss-git-test-{}", safe_name));
    let _ = std::fs::remove_dir_all(&tmp_dir);
    let manager = GitManager::init_repo(&tmp_dir, None).unwrap();
    (tmp_dir, manager)
}

#[test]
fn test_init_repo() {
    let (tmp_dir, _manager) = temp_git_repo();
    assert!(tmp_dir.join(".git").exists());
    assert!(tmp_dir.join("README.md").exists());
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_open_repo() {
    let (tmp_dir, _manager) = temp_git_repo();
    let opened = GitManager::open(&tmp_dir).unwrap();
    assert_eq!(opened.repo_path(), tmp_dir.as_path());
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

#[test]
fn test_create_branch() {
    let (_tmp_dir, manager) = temp_git_repo();
    let result = manager
        .create_branch("game_logic.dll", "DrawSprite", 1)
        .unwrap();
    assert!(result.created);
    assert_eq!(result.branch.name, "re/game_logic/DrawSpritev1");
    assert_eq!(result.branch.dll, "game_logic.dll");
    assert_eq!(result.branch.function, "DrawSprite");
    assert_eq!(result.branch.attempt, 1);
}

#[test]
fn test_create_branch_reuses_existing() {
    let (_tmp_dir, manager) = temp_git_repo();
    let result1 = manager
        .create_branch("game_logic.dll", "DrawSprite", 1)
        .unwrap();
    assert!(result1.created);
    let result2 = manager
        .create_branch("game_logic.dll", "DrawSprite", 1)
        .unwrap();
    assert!(!result2.created);
    assert_eq!(result2.branch.name, "re/game_logic/DrawSpritev1");
}

#[test]
fn test_branch_naming() {
    assert_eq!(
        GitBranch::new("game_logic.dll", "DrawSprite", 1)
            .unwrap()
            .name,
        "re/game_logic/DrawSpritev1"
    );
    assert_eq!(
        GitBranch::new("directx_render.dll", "Present", 3)
            .unwrap()
            .name,
        "re/directx_render/Presentv3"
    );
}

#[test]
fn test_commit() {
    let (_tmp_dir, manager) = temp_git_repo();
    let branch_result = manager
        .create_branch("game_logic.dll", "DrawSprite", 1)
        .unwrap();
    let branch = branch_result.branch;

    let test_file = manager
        .repo_path()
        .join("src")
        .join("modules")
        .join("test.rs");
    std::fs::create_dir_all(test_file.parent().unwrap()).unwrap();
    std::fs::write(&test_file, "fn test() {}").unwrap();

    let commit = manager
        .commit(
            &branch,
            "re/translation/DrawSprite: translate DrawSprite to Rust",
            &["src/modules/test.rs"],
        )
        .unwrap();

    assert!(!commit.hash.is_empty());
    assert_eq!(commit.branch, "re/game_logic/DrawSpritev1");
    assert_eq!(commit.files, vec!["src/modules/test.rs".to_string()]);
}

#[test]
fn test_merge_to_main() {
    let (tmp_dir, manager) = temp_git_repo();
    let branch_result = manager
        .create_branch("game_logic.dll", "DrawSprite", 1)
        .unwrap();
    let branch = branch_result.branch;

    // Create a file
    let test_file = tmp_dir.join("merged_test.rs");
    std::fs::write(&test_file, "fn merged() {}").unwrap();

    // Stage the file directly using git2 Index API
    let mut index = manager.repo().index().unwrap();
    // add_path uses git2's internal path resolution
    index
        .add_path(std::path::Path::new("merged_test.rs"))
        .unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = manager.repo().find_tree(tree_id).unwrap();

    let head = manager.repo().head().unwrap();
    let parent_oid = head.target().unwrap();
    let parent = manager.repo().find_commit(parent_oid).unwrap();
    let sig = git2::Signature::now("Calxgloss", "calxgloss@system").unwrap();

    let commit_oid = manager
        .repo()
        .commit(
            Some(&format!("refs/heads/{}", branch.name)),
            &sig,
            &sig,
            "re/translation: add merged test",
            &tree,
            &[&parent],
        )
        .unwrap();

    let commit = GitCommit {
        branch: branch.name.clone(),
        message: "re/translation: add merged test".to_string(),
        hash: commit_oid.to_string(),
        files: vec!["merged_test.rs".to_string()],
    };

    let result = manager.merge_to_main(&branch).unwrap();
    match result {
        MergeResult::Merged { merge_hash } => {
            assert_eq!(merge_hash, commit.hash);
        }
        MergeResult::AlreadyUpToDate => {
            panic!("Expected merge, got AlreadyUpToDate");
        }
        MergeResult::Conflicts { .. } => {
            panic!("Unexpected merge conflicts");
        }
    }

    assert_eq!(manager.current_branch().unwrap(), "main");
}

#[test]
fn test_merge_already_ancestor() {
    let (_tmp_dir, manager) = temp_git_repo();
    let branch_result = manager
        .create_branch("game_logic.dll", "DrawSprite", 1)
        .unwrap();
    let branch = branch_result.branch;

    let result = manager.merge_to_main(&branch).unwrap();
    assert!(matches!(result, MergeResult::AlreadyUpToDate));
}

#[test]
fn test_current_branch() {
    let (_tmp_dir, manager) = temp_git_repo();
    assert_eq!(manager.current_branch().unwrap(), "main");
}

#[test]
fn test_list_branches() {
    let (_tmp_dir, manager) = temp_git_repo();
    let branches = manager.list_branches().unwrap();
    assert!(branches.contains(&"main".to_string()));

    manager.create_branch("test.dll", "FuncA", 1).unwrap();
    manager.create_branch("test.dll", "FuncB", 2).unwrap();

    let branches = manager.list_branches().unwrap();
    assert!(branches.contains(&"re/test/FuncAv1".to_string()));
    assert!(branches.contains(&"re/test/FuncBv2".to_string()));
    assert!(branches.contains(&"main".to_string()));
}

#[test]
fn test_list_translation_branches() {
    let (_tmp_dir, manager) = temp_git_repo();
    manager.create_branch("test.dll", "FuncA", 1).unwrap();
    manager.create_branch("other.dll", "FuncB", 1).unwrap();

    let translation_branches = manager.list_translation_branches().unwrap();
    assert_eq!(translation_branches.len(), 2);
    assert!(translation_branches.iter().any(|b| b == "re/test/FuncAv1"));
    assert!(translation_branches.iter().any(|b| b == "re/other/FuncBv1"));
    assert!(!translation_branches.iter().any(|b| b == "main"));
}

#[test]
fn test_delete_branch() {
    let (_tmp_dir, manager) = temp_git_repo();
    manager.create_branch("test.dll", "FuncA", 1).unwrap();
    // Switch back to main before deleting
    let main_ref = manager
        .repo()
        .find_branch("main", git2::BranchType::Local)
        .unwrap();
    let main_commit = main_ref.get().peel_to_commit().unwrap();
    let main_obj = main_commit.as_object();
    let mut checkout_opts = git2::build::CheckoutBuilder::new();
    checkout_opts.force();
    manager.repo().set_head("refs/heads/main").unwrap();
    manager
        .repo()
        .reset(main_obj, ResetType::Hard, Some(&mut checkout_opts))
        .unwrap();

    let branches = manager.list_branches().unwrap();
    assert!(branches.contains(&"re/test/FuncAv1".to_string()));

    manager.delete_branch("re/test/FuncAv1").unwrap();
    let branches = manager.list_branches().unwrap();
    assert!(!branches.contains(&"re/test/FuncAv1".to_string()));
}

#[test]
fn test_delete_main_blocked() {
    let (_tmp_dir, manager) = temp_git_repo();
    let result = manager.delete_branch("main");
    assert!(result.is_err());
}

#[test]
fn test_store_failure() {
    let (tmp_dir, manager) = temp_git_repo();
    let branch_result = manager
        .create_branch("game_logic.dll", "DrawSprite", 1)
        .unwrap();
    let branch = branch_result.branch;

    let commit = manager
        .commit(&branch, "re/translation: failed attempt", &[])
        .unwrap();

    let patch_path = manager
        .store_failure(
            &branch,
            "Compilation failed",
            &["error[E0308]: mismatched types".to_string()],
            &["test_input_3: expected 42, got 43".to_string()],
            &commit.hash,
        )
        .unwrap();

    assert!(patch_path.exists());
    assert_eq!(
        patch_path.parent().unwrap(),
        tmp_dir
            .join("re")
            .join("patches")
            .join("game_logic.dll")
            .join("DrawSprite")
    );

    let content = std::fs::read_to_string(&patch_path).unwrap();
    let record: PatchRecord = serde_json::from_str(&content).unwrap();
    assert_eq!(record.dll, "game_logic.dll");
    assert_eq!(record.function, "DrawSprite");
    assert_eq!(record.attempt, 1);
    assert_eq!(record.error_message, "Compilation failed");
    assert_eq!(record.compilation_errors.len(), 1);
    assert_eq!(record.test_failures.len(), 1);
}

#[test]
fn test_working_dir_status() {
    let (_tmp_dir, manager) = temp_git_repo();
    let test_file = manager.repo_path().join("untracked.rs");
    std::fs::write(&test_file, "// untracked").unwrap();

    let status = manager.working_dir_status().unwrap();
    assert!(status.iter().any(|(path, _)| path == "untracked.rs"));
}

#[test]
fn test_current_commit() {
    let (_tmp_dir, manager) = temp_git_repo();
    let commit = manager.current_commit().unwrap();
    assert_eq!(commit.len(), 40);
}

#[test]
fn test_git_branch_validation() {
    assert!(GitBranch::new("", "Func", 1).is_err());
    assert!(GitBranch::new("dll.dll", "", 1).is_err());
}
