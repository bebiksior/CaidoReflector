import fs from "node:fs/promises";
import path from "path";

async function updateReflectorJson() {
  try {
    const reflectorJsonPath = path.join(process.cwd(), "Reflector.json");
    const reflectorJson = JSON.parse(
      await fs.readFile(reflectorJsonPath, "utf8")
    );

    const reflectorJsPath = path.join(process.cwd(), "final", "reflector.js");
    const reflectorJsContent = await fs.readFile(reflectorJsPath, "utf8");

    reflectorJson.graph.nodes[2].inputs[2].value.data = reflectorJsContent;

    await fs.writeFile(
      reflectorJsonPath,
      JSON.stringify(reflectorJson, null, 2)
    );

    console.log("Reflector.json updated successfully.");
  } catch (err) {
    console.error("Error:", err);
  }
}

Bun.build({
  entrypoints: ["src/reflector.ts"],
  outdir: "final",
  minify: true,
}).then(() => {
  console.log("Reflector.js built successfully.");
  updateReflectorJson();
});
