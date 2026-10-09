use super::*;
use git2::ResetType;
use std::env;
use std::path::PathBuf;

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
        .create_branch("game_logic.dll", "DrawSprite", 1, None)
        .unwrap();
    assert!(result.created);
    assert_eq!(result.branch.name, "re/game_logic.dll/DrawSpritev1");
    assert_eq!(result.branch.dll, "game_logic.dll");
    assert_eq!(result.branch.function, "DrawSprite");
    assert_eq!(result.branch.attempt, 1);
}

#[test]
fn test_create_branch_reuses_existing() {
    let (_tmp_dir, manager) = temp_git_repo();
    let result1 = manager
        .create_branch("game_logic.dll", "DrawSprite", 1, None)
        .unwrap();
    assert!(result1.created);
    let result2 = manager
        .create_branch("game_logic.dll", "DrawSprite", 1, None)
        .unwrap();
    assert!(!result2.created);
    assert_eq!(result2.branch.name, "re/game_logic.dll/DrawSpritev1");
}

#[test]
fn test_branch_naming() {
    assert_eq!(
        GitBranch::new("game_logic.dll", "DrawSprite", 1)
            .unwrap()
            .name,
        "re/game_logic.dll/DrawSpritev1"
    );
    assert_eq!(
        GitBranch::new("directx_render.dll", "Present", 3)
            .unwrap()
            .name,
        "re/directx_render.dll/Presentv3"
    );
}

#[test]
fn test_commit() {
    let (_tmp_dir, manager) = temp_git_repo();
    let branch_result = manager
        .create_branch("game_logic.dll", "DrawSprite", 1, None)
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
    assert_eq!(commit.branch, "re/game_logic.dll/DrawSpritev1");
    assert_eq!(commit.files, vec!["src/modules/test.rs".to_string()]);
}

#[test]
fn test_merge_to_main() {
    let (tmp_dir, manager) = temp_git_repo();
    let branch_result = manager
        .create_branch("game_logic.dll", "DrawSprite", 1, None)
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
        .create_branch("game_logic.dll", "DrawSprite", 1, None)
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

    manager.create_branch("test.dll", "FuncA", 1, None).unwrap();
    manager.create_branch("test.dll", "FuncB", 2, None).unwrap();

    let branches = manager.list_branches().unwrap();
    assert!(branches.contains(&"re/test.dll/FuncAv1".to_string()));
    assert!(branches.contains(&"re/test.dll/FuncBv2".to_string()));
    assert!(branches.contains(&"main".to_string()));
}

#[test]
fn test_list_translation_branches() {
    let (_tmp_dir, manager) = temp_git_repo();
    manager.create_branch("test.dll", "FuncA", 1, None).unwrap();
    manager
        .create_branch("other.dll", "FuncB", 1, None)
        .unwrap();

    let translation_branches = manager.list_translation_branches().unwrap();
    assert_eq!(translation_branches.len(), 2);
    assert!(
        translation_branches
            .iter()
            .any(|b| b == "re/test.dll/FuncAv1")
    );
    assert!(
        translation_branches
            .iter()
            .any(|b| b == "re/other.dll/FuncBv1")
    );
    assert!(!translation_branches.iter().any(|b| b == "main"));
}

#[test]
fn test_delete_branch() {
    let (_tmp_dir, manager) = temp_git_repo();
    manager.create_branch("test.dll", "FuncA", 1, None).unwrap();
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
    assert!(branches.contains(&"re/test.dll/FuncAv1".to_string()));

    manager.delete_branch("re/test.dll/FuncAv1").unwrap();
    let branches = manager.list_branches().unwrap();
    assert!(!branches.contains(&"re/test.dll/FuncAv1".to_string()));
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
        .create_branch("game_logic.dll", "DrawSprite", 1, None)
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

// ============================================================
// Dependency checker tests
// ============================================================

#[test]
fn test_shim_dependency_map_known_dlls() {
    let map = ShimDependencyMap::new();
    assert_eq!(map.get("d3d9.dll"), Some("wgpu"));
    assert_eq!(map.get("d3d11.dll"), Some("wgpu"));
    assert_eq!(map.get("fmod.dll"), Some("fmod-rs"));
    assert_eq!(map.get("openal32.dll"), Some("cpal"));
    assert_eq!(map.get("d2d1.dll"), Some("tiny-skia"));
    assert_eq!(map.get("unknown.dll"), None);
}

#[test]
fn test_dependency_checker_shim_branch_name() {
    let checker = DependencyChecker::new();
    assert_eq!(
        checker.shim_branch_name("d3d9.dll"),
        Some("re/shim/wgpu".to_string())
    );
    assert_eq!(
        checker.shim_branch_name("fmod.dll"),
        Some("re/shim/fmod-rs".to_string())
    );
    assert_eq!(checker.shim_branch_name("game_logic.dll"), None);
}

#[test]
fn test_dependency_check_no_deps_for_project_specific() {
    let checker = DependencyChecker::new();
    let result = checker.check(
        "game_logic.dll",
        &DllCategory::ProjectSpecific,
        None::<&str>,
    );
    assert!(result.is_complete());
    assert!(result.required.is_empty());
    assert!(result.unmet.is_empty());
}

#[test]
fn test_dependency_check_no_deps_for_windows_os() {
    let checker = DependencyChecker::new();
    let result = checker.check("kernel32.dll", &DllCategory::WindowsOs, None::<&str>);
    assert!(result.is_complete());
    assert!(result.required.is_empty());
}

#[test]
fn test_dependency_check_finds_shim_for_microsoft_sdk() {
    let checker = DependencyChecker::new();
    let result = checker.check("d3d9.dll", &DllCategory::MicrosoftSdk, Some("wgpu"));
    assert!(!result.is_complete());
    assert_eq!(result.required.len(), 1);
    assert!(result.required.iter().any(|s| s == "re/shim/wgpu"));
    assert!(result.has_unmet());
}

#[test]
fn test_dependency_check_finds_shim_for_known_third_party() {
    let checker = DependencyChecker::new();
    let result = checker.check("fmod.dll", &DllCategory::KnownThirdParty, Some("fmod-rs"));
    assert!(!result.is_complete());
    assert_eq!(result.required.len(), 1);
    assert!(result.required.iter().any(|s| s == "re/shim/fmod-rs"));
}

#[test]
fn test_dependency_check_fallback_to_crate_replacement() {
    let checker = DependencyChecker::new();
    // Unknown DLL but with crate_replacement info
    let result = checker.check(
        "my_vendor.dll",
        &DllCategory::MicrosoftSdk,
        Some("my-crate"),
    );
    assert!(!result.is_complete());
    assert!(result.required.iter().any(|s| s == "re/shim/my-crate"));
}

#[test]
fn test_create_branch_skip_policy() {
    let (_tmp_dir, manager) = temp_git_repo();
    // Skip policy — should always succeed even with unmet deps
    let policy = BranchCreationPolicy::Skip;
    let result = manager.create_branch("d3d9.dll", "Present", 1, Some(&policy));
    assert!(result.is_ok());
    assert!(result.unwrap().created);
}

#[test]
fn test_create_branch_with_none_policy() {
    let (_tmp_dir, manager) = temp_git_repo();
    // None policy — same as Skip (backwards-compatible)
    let result = manager.create_branch("d3d9.dll", "Present", 1, None);
    assert!(result.is_ok());
    assert!(result.unwrap().created);
}

#[test]
fn test_create_branch_enforce_blocks_unmet_deps() {
    let (_tmp_dir, manager) = temp_git_repo();
    // Enforce policy with unmet shim dependency — should fail
    let policy = BranchCreationPolicy::Enforce(DependencyPolicy {
        category: DllCategory::MicrosoftSdk,
        crate_replacement: Some("wgpu".to_string()),
    });
    let result = manager.create_branch("d3d9.dll", "Present", 1, Some(&policy));
    // Should fail because re/shim/wgpu is not merged into main
    assert!(result.is_err());
    let err = result.unwrap_err();
    let err_msg = format!("{}", err);
    assert!(
        err_msg.contains("unmet dependencies"),
        "Error should mention unmet dependencies, got: {}",
        err_msg
    );
}

#[test]
fn test_create_branch_enforce_allows_merged_shim() {
    let (tmp_dir, manager) = temp_git_repo();

    // Use a unique branch name to avoid collisions between test runs
    let shim_branch_name = "re/shim/wgpu";

    // Create the shim branch manually to simulate a pre-existing merged shim
    let main_ref = manager
        .repo()
        .find_branch("main", git2::BranchType::Local)
        .unwrap();
    let main_commit = main_ref.get().peel_to_commit().unwrap();
    manager
        .repo()
        .branch(shim_branch_name, &main_commit, false)
        .unwrap();

    // Make a commit on the shim branch so it's not just main
    let shim_file = tmp_dir.join("shim.rs");
    std::fs::write(&shim_file, "fn wgpu_bridge() {}").unwrap();
    let mut index = manager.repo().index().unwrap();
    index.add_path(std::path::Path::new("shim.rs")).unwrap();
    let tree_id = index.write_tree().unwrap();
    let tree = manager.repo().find_tree(tree_id).unwrap();
    let sig = git2::Signature::now("Calxgloss", "calxgloss@system").unwrap();
    let shim_commit_oid = manager
        .repo()
        .commit(
            Some(shim_branch_name),
            &sig,
            &sig,
            "re/shim/wgpu: add wgpu shim",
            &tree,
            &[&main_commit],
        )
        .unwrap();

    // Fast-forward main to include the shim commit
    manager
        .repo()
        .reference("refs/heads/main", shim_commit_oid, true, "FF to shim")
        .unwrap();

    let mut checkout_opts = git2::build::CheckoutBuilder::new();
    checkout_opts.force();
    manager.repo().set_head("refs/heads/main").unwrap();
    manager
        .repo()
        .reset(
            main_commit.as_object(),
            ResetType::Hard,
            Some(&mut checkout_opts),
        )
        .unwrap();

    // Now enforce policy should succeed because shim is merged into main
    let policy = BranchCreationPolicy::Enforce(DependencyPolicy {
        category: DllCategory::MicrosoftSdk,
        crate_replacement: Some("wgpu".to_string()),
    });
    let result = manager.create_branch("d3d9.dll", "Present", 1, Some(&policy));
    assert!(
        result.is_ok(),
        "Should succeed when shim is already merged: {:?}",
        result
    );
}

#[test]
fn test_create_branch_warn_continues_on_unmet() {
    let (_tmp_dir, manager) = temp_git_repo();
    // Warn policy — should succeed but warn about unmet deps
    let policy = BranchCreationPolicy::Warn(DependencyPolicy {
        category: DllCategory::MicrosoftSdk,
        crate_replacement: Some("wgpu".to_string()),
    });
    let result = manager.create_branch("d3d9.dll", "Present", 1, Some(&policy));
    // Should succeed despite unmet deps
    assert!(result.is_ok());
    assert!(result.unwrap().created);
}
