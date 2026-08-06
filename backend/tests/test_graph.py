import os
import tempfile
import json
from unittest.mock import patch
from src.graph import build_graph, get_graph_context
import src.memory
import src.config

def test_graph_building_and_context():
    # 1. Mock a tiny repo structure on disk
    with tempfile.TemporaryDirectory() as temp_repo:
        os.makedirs(os.path.join(temp_repo, "app", "models"))
        
        main_py = os.path.join(temp_repo, "app", "main.py")
        with open(main_py, "w") as f:
            f.write("from app.models.user import User\nimport utils\n")
            
        user_py = os.path.join(temp_repo, "app", "models", "user.py")
        with open(user_py, "w") as f:
            f.write("class User:\n    pass\n")
            
        utils_py = os.path.join(temp_repo, "app", "utils.py")
        with open(utils_py, "w") as f:
            f.write("def helper():\n    pass\n")
            
        source_files = [
            "app/main.py",
            "app/models/user.py",
            "app/utils.py"
        ]
        
        # 2. Build Graph
        graph = build_graph("test_project", temp_repo, source_files)
        
        # Verify graph structure
        assert "app/models/user.py" in graph["app/main.py"]["imports"]
        assert "app/utils.py" in graph["app/main.py"]["imports"]
        assert "app/main.py" in graph["app/models/user.py"]["imported_by"]
        
        # 3. Test get_graph_context
        # We need to mock memory.get_graph and config.REPORTS_DIR
        with patch('src.memory.get_graph') as mock_get_graph:
            with patch('src.config.REPOS_DIR', new=os.path.join(temp_repo, "repos")):
                # When get_graph is called, return our graph
                mock_get_graph.return_value = graph
                
                # Create the reports/../repos/test_project dir structure so get_graph_context can find files
                repos_dir = os.path.join(temp_repo, "repos", "test_project")
                os.makedirs(os.path.join(repos_dir, "app", "models"))
                for f in source_files:
                    with open(os.path.join(repos_dir, f), "w") as dst:
                        with open(os.path.join(temp_repo, f), "r") as src:
                            dst.write(src.read())
                
                # Fetch context for app/main.py (1-hop)
                context = get_graph_context("test_project", "app/main.py", max_hops=1)
                
                assert "--- FILE: app/main.py ---" in context
                assert "--- FILE: app/models/user.py ---" in context
                assert "--- FILE: app/utils.py ---" in context
                
                # Fetch context for app/models/user.py (1-hop)
                context2 = get_graph_context("test_project", "app/models/user.py", max_hops=1)
                assert "--- FILE: app/main.py ---" in context2
                assert "--- FILE: app/models/user.py ---" in context2
                assert "--- FILE: app/utils.py ---" not in context2

if __name__ == "__main__":
    test_graph_building_and_context()
    print("All tests passed!")
