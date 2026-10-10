/* ==========================================================================
   Dependency graph export — SVG / PNG downloads of the current graph
   (issue #79). Both formats come from the same SVG serialization
   (GraphRenderer.toSVG), so the PNG matches the SVG rather than only the
   current viewport crop of the live canvas.
   ========================================================================== */

function downloadBlob(blob, filename) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

// Download the visible (post-filter) graph as a standalone .svg file.
export function exportGraphSVG(renderer) {
    const svg = renderer.toSVG();
    downloadBlob(new Blob([svg], { type: "image/svg+xml" }), "calxgloss-graph.svg");
}

// Rasterize the same SVG at 2× and download it as .png. Resolves true when
// the PNG was produced, false when rasterization or encoding failed.
export async function exportGraphPNG(renderer) {
    const svg = renderer.toSVG();
    const url = URL.createObjectURL(new Blob([svg], { type: "image/svg+xml" }));
    try {
        const img = new Image();
        const loaded = await new Promise((resolve) => {
            img.onload = () => resolve(true);
            img.onerror = () => resolve(false);
            img.src = url;
        });
        if (!loaded) return false;

        const SCALE = 2;
        const canvas = document.createElement("canvas");
        canvas.width = Math.max(1, Math.round(img.width * SCALE));
        canvas.height = Math.max(1, Math.round(img.height * SCALE));
        const ctx = canvas.getContext("2d");
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

        const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/png"));
        if (!blob) return false;
        downloadBlob(blob, "calxgloss-graph.png");
        return true;
    } finally {
        URL.revokeObjectURL(url);
    }
}
