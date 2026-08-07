import os
import ast
import re

def _extract_references(file_path: str, content: str) -> list[str]:
    """Extracts imported modules or referenced files from the given file content."""
    ext = os.path.splitext(file_path)[1].lower()
    refs = set()
    
    if ext == ".py":
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        refs.add(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        refs.add(node.module)
        except Exception:
            pass
            
    elif ext in [".js", ".jsx", ".ts", ".tsx"]:
        # import ... from '...' and export ... from '...'
        for m in re.finditer(r"(?:from|import)\s+['\"]([^'\"]+)['\"]", content):
            refs.add(m.group(1))
        # require('...')
        for m in re.finditer(r"require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", content):
            refs.add(m.group(1))
        # dynamic import('...')
        for m in re.finditer(r"import\s*\(\s*['\"]([^'\"]+)['\"]\s*\)", content):
            refs.add(m.group(1))
            
    elif ext in [".html", ".htm"]:
        # <script src="...">
        for m in re.finditer(r"<script\s+[^>]*src=['\"]([^'\"]+)['\"]", content):
            refs.add(m.group(1))
        # <link href="...">
        for m in re.finditer(r"<link\s+[^>]*href=['\"]([^'\"]+)['\"]", content):
            refs.add(m.group(1))
            
    return list(refs)

def _resolve_reference(ref: str, current_file: str, all_files: list[str]) -> str | None:
    """Attempts to match a raw import string to a physical file path in the repo."""
    ref_as_path = ref.replace('.', '/')
    clean_ref = ref.strip("./\\")
    
    possible_suffixes = [
        f"{ref_as_path}.py",
        f"{ref_as_path}.js",
        f"{ref_as_path}.ts",
        f"{ref_as_path}.jsx",
        f"{ref_as_path}.tsx",
        f"{ref_as_path}/__init__.py",
        f"{ref_as_path}/index.js",
        f"{ref_as_path}/index.ts",
        clean_ref,
        clean_ref.split("/")[-1]
    ]
    
    for f in all_files:
        for suf in possible_suffixes:
            if f.endswith(suf) or f == suf:
                return f
                
    return None

def build_graph(project_id: str, repo_path: str, source_files: list[str]) -> dict:
    """
    Builds a bidirectional dependency graph for the given source files.
    Returns: { file_path: {"imports": [], "imported_by": []} }
    """
    graph = {f: {"imports": [], "imported_by": []} for f in source_files}
    
    for f in source_files:
        full_path = os.path.join(repo_path, f)
        if not os.path.exists(full_path):
            continue
            
        try:
            with open(full_path, "r", encoding="utf-8") as file_obj:
                content = file_obj.read()
        except Exception:
            continue
            
        refs = _extract_references(f, content)
        for ref in refs:
            resolved = _resolve_reference(ref, f, source_files)
            if resolved and resolved != f:
                if resolved not in graph[f]["imports"]:
                    graph[f]["imports"].append(resolved)
                if f not in graph[resolved]["imported_by"]:
                    graph[resolved]["imported_by"].append(f)
                    
    return graph

def get_graph_context(project_id: str, file_path: str, max_hops: int = 1) -> str:
    """
    Retrieves the target file and its 1-hop dependencies from the graph,
    returning their concatenated full contents as a string for LLM context.
    """
    from . import memory
    from . import config
    
    graph = memory.get_graph(project_id)
    if not graph or file_path not in graph:
        return ""
        
    deps = set([file_path])
    if max_hops >= 1:
        deps.update(graph[file_path].get("imports", []))
        deps.update(graph[file_path].get("imported_by", []))
        
    if len(deps) == 1:
        return ""
        
    repo_path = os.path.join(config.REPOS_DIR, project_id)
    
    context_parts = []
    for dep in sorted(list(deps)):
        full_path = os.path.join(repo_path, dep)
        if os.path.exists(full_path):
            try:
                with open(full_path, "r", encoding="utf-8") as f:
                    content = f.read()
                context_parts.append(f"--- FILE: {dep} ---\n{content}\n")
            except Exception:
                pass
                
    return "\n".join(context_parts)
