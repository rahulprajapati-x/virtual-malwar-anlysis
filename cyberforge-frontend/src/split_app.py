import os
import sys
import re

base_dir = "/Users/rahul/Desktop/projects/vertual malwar anlysis /cyberforge-frontend/src"
app_file = os.path.join(base_dir, "App.jsx")

sections = {
    "api/client.js": (55, 196, ["createApiClient", "TokenStore"]),
    "utils/helpers.js": (197, 225, ["scoreToThreat", "sevColor", "fmtBytes"]),
    "components/Toast.jsx": (226, 263, ["ToastProvider", "useToast"]),
    "components/GlobalSearch.jsx": (265, 356, ["GlobalSearchModal"]),
    "components/NotifPanel.jsx": (358, 412, ["NotifProvider", "useNotif", "NotifPanel"]),
    "components/LoginScreen.jsx": (414, 517, ["LoginScreen"]),
    "hooks/useBackend.js": (519, 549, ["useBackend"]),
    "components/SharedComponents.jsx": (551, 739, []),
    "components/ExplanationModal.jsx": (741, 781, ["ExplanationModal"]),
    "pages/Dashboard.jsx": (783, 1106, ["Dashboard"]),
    "pages/FileUpload.jsx": (1107, 1218, ["FileUpload"]),
    "pages/StaticStream.jsx": (1219, 1335, ["StaticStream"]),
    "pages/SandboxSimulator.jsx": (1336, 1721, ["SandboxSimulator"]),
    "pages/SandboxTimeline.jsx": (1722, 1766, ["SandboxTimeline"]),
    "pages/MachineHarmReport.jsx": (1767, 2067, ["MachineHarmReport"]),
    "pages/SandboxResults.jsx": (2068, 2345, ["SandboxResults"]),
    "pages/AnalysisResults.jsx": (2346, 3218, ["AnalysisResults"]),
    "pages/CipherAI.jsx": (3219, 3305, ["CipherAI"]),
    "pages/Cases.jsx": (3306, 3424, ["Cases"]),
    "pages/MitreMatrix.jsx": (3425, 3478, ["MitreMatrix"]),
    "pages/IocDatabase.jsx": (3479, 3576, ["IocDatabase"]),
    "pages/Settings.jsx": (3577, 3778, ["Settings"]),
    "pages/VirtualEnvironment.jsx": (3779, 3898, ["VirtualEnvironment"]),
    "pages/PcapAnalyzer.jsx": (3899, 4278, ["PcapAnalyzer"]),
    "pages/MemoryForensics.jsx": (4279, 4521, ["MemoryForensics"]),
    "pages/CaseTimeline.jsx": (4522, 4674, ["CaseTimeline"]),
}

with open(app_file, "r") as f:
    lines = f.readlines()

imports = "".join(lines[0:53])

for path, (start, end, exports) in sections.items():
    content = "".join(lines[start-1:end])
    full_path = os.path.join(base_dir, path)
    os.makedirs(os.path.dirname(full_path), exist_ok=True)
    
    with open(full_path, "w") as f:
        f.write(imports + "\n" + content)
        
        # Add exports
        if exports:
            # check if default export
            if len(exports) == 1 and exports[0] not in ["createApiClient", "TokenStore", "scoreToThreat", "sevColor", "fmtBytes", "useBackend", "ToastProvider", "useToast", "NotifProvider", "useNotif", "NotifPanel", "GlobalSearchModal"]:
                f.write(f"\nexport default {exports[0]};\n")
            else:
                f.write(f"\nexport {{ {', '.join(exports)} }};\n")
        
        # SharedComponents need some explicit exports if there are multiple.
        # But wait, Shared components just defines a bunch of functions. We can just export them all.
        if "SharedComponents.jsx" in path:
            components = re.findall(r"const\s+([A-Z][a-zA-Z0-9_]*)\s*=", content)
            f.write(f"\nexport {{ {', '.join(components)} }};\n")

# Rewrite App.jsx
app_content = "".join(lines[0:53]) # Keep imports and ErrorBoundary

app_content += """
import { createApiClient, TokenStore } from './api/client';
import { scoreToThreat, sevColor, fmtBytes } from './utils/helpers';
import { ToastProvider, useToast } from './components/Toast';
import { GlobalSearchModal } from './components/GlobalSearch';
import { NotifProvider, useNotif, NotifPanel } from './components/NotifPanel';
import LoginScreen from './components/LoginScreen';
import { useBackend } from './hooks/useBackend';
import { Card, AnimatedCard, ProgressBar, LoadingSpinner, Tabs, Badge, ActionButton, FileIcon, Modal } from './components/SharedComponents';
import ExplanationModal from './components/ExplanationModal';
import Dashboard from './pages/Dashboard';
import FileUpload from './pages/FileUpload';
import StaticStream from './pages/StaticStream';
import SandboxSimulator from './pages/SandboxSimulator';
import SandboxTimeline from './pages/SandboxTimeline';
import MachineHarmReport from './pages/MachineHarmReport';
import SandboxResults from './pages/SandboxResults';
import AnalysisResults from './pages/AnalysisResults';
import CipherAI from './pages/CipherAI';
import Cases from './pages/Cases';
import MitreMatrix from './pages/MitreMatrix';
import IocDatabase from './pages/IocDatabase';
import Settings from './pages/Settings';
import VirtualEnvironment from './pages/VirtualEnvironment';
import PcapAnalyzer from './pages/PcapAnalyzer';
import MemoryForensics from './pages/MemoryForensics';
import CaseTimeline from './pages/CaseTimeline';

"""

app_content += "".join(lines[4674:])

with open(app_file, "w") as f:
    f.write(app_content)

print("Split completed successfully!")
