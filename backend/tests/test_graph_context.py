import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.graph import get_graph_context, build_graph

def test_graph_context_with_imports(tmp_path, monkeypatch):
    repo_dir = tmp_path / "proj-test-1"
    repo_dir.mkdir()
    
    (repo_dir / "main.py").write_text("import helper\nhelper.do_something()")
    (repo_dir / "helper.py").write_text("def do_something(): pass")
    
    files = [f.name for f in repo_dir.iterdir() if f.is_file()]
    graph = build_graph("proj-test-1", str(repo_dir), files)
    
    monkeypatch.setattr("src.memory.get_graph", lambda x: graph)
    monkeypatch.setattr("src.config.REPOS_DIR", str(tmp_path))
    
    context = get_graph_context("proj-test-1", "main.py")
    assert "main.py" in context
    assert "helper.py" in context

def test_graph_context_isolated(tmp_path, monkeypatch):
    repo_dir = tmp_path / "proj-test-2"
    repo_dir.mkdir()
    
    (repo_dir / "standalone.py").write_text("print('hello')")
    
    files = [f.name for f in repo_dir.iterdir() if f.is_file()]
    graph = build_graph("proj-test-2", str(repo_dir), files)
    
    monkeypatch.setattr("src.memory.get_graph", lambda x: graph)
    monkeypatch.setattr("src.config.REPOS_DIR", str(tmp_path))
    
    context = get_graph_context("proj-test-2", "standalone.py")
    assert context == "" 

def test_graph_context_dynamic_import(tmp_path, monkeypatch):
    repo_dir = tmp_path / "proj-test-3"
    repo_dir.mkdir()
    
    (repo_dir / "index.js").write_text("import('./module.js')")
    (repo_dir / "module.js").write_text("export const x = 1;")
    
    files = [f.name for f in repo_dir.iterdir() if f.is_file()]
    graph = build_graph("proj-test-3", str(repo_dir), files)
    
    monkeypatch.setattr("src.memory.get_graph", lambda x: graph)
    monkeypatch.setattr("src.config.REPOS_DIR", str(tmp_path))
    
    context = get_graph_context("proj-test-3", "index.js")
    assert "index.js" in context
    assert "module.js" in context

def test_graph_context_export_from(tmp_path, monkeypatch):
    repo_dir = tmp_path / "proj-test-4"
    repo_dir.mkdir()
    
    (repo_dir / "index.js").write_text("export * from './module.js'")
    (repo_dir / "module.js").write_text("export const x = 1;")
    
    files = [f.name for f in repo_dir.iterdir() if f.is_file()]
    graph = build_graph("proj-test-4", str(repo_dir), files)
    
    monkeypatch.setattr("src.memory.get_graph", lambda x: graph)
    monkeypatch.setattr("src.config.REPOS_DIR", str(tmp_path))
    
    context = get_graph_context("proj-test-4", "index.js")
    assert "module.js" in context

def test_graph_context_html_tags(tmp_path, monkeypatch):
    repo_dir = tmp_path / "proj-test-5"
    repo_dir.mkdir()
    
    (repo_dir / "index.html").write_text('<script src="app.js"></script><link href="style.css">')
    (repo_dir / "app.js").write_text("console.log('hi')")
    (repo_dir / "style.css").write_text("body { color: red; }")
    
    files = [f.name for f in repo_dir.iterdir() if f.is_file()]
    graph = build_graph("proj-test-5", str(repo_dir), files)
    
    monkeypatch.setattr("src.memory.get_graph", lambda x: graph)
    monkeypatch.setattr("src.config.REPOS_DIR", str(tmp_path))
    
    context = get_graph_context("proj-test-5", "index.html")
    assert "app.js" in context
    assert "style.css" in context

def test_graph_reindex_stale_edges(tmp_path, monkeypatch):
    repo_dir = tmp_path / "proj-test-6"
    repo_dir.mkdir()
    
    (repo_dir / "index.js").write_text("import './old.js'")
    (repo_dir / "old.js").write_text("console.log('old')")
    
    files = [f.name for f in repo_dir.iterdir() if f.is_file()]
    build_graph("proj-test-6", str(repo_dir), files)
    
    (repo_dir / "index.js").write_text("import './new.js'")
    (repo_dir / "new.js").write_text("console.log('new')")
    (repo_dir / "old.js").unlink()
    
    files = [f.name for f in repo_dir.iterdir() if f.is_file()]
    graph = build_graph("proj-test-6", str(repo_dir), files)
    
    monkeypatch.setattr("src.memory.get_graph", lambda x: graph)
    monkeypatch.setattr("src.config.REPOS_DIR", str(tmp_path))
    
    context = get_graph_context("proj-test-6", "index.js")
    assert "new.js" in context
    assert "old.js" not in context
