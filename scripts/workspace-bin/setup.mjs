import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..', '..');
const sourceDir = path.join(repoRoot, 'scripts', 'workspace-bin');
const targetDir = path.join(repoRoot, 'node_modules', '.bin');

async function ensureTargetDir() {
  await fs.mkdir(targetDir, { recursive: true });
}

async function createLink(source, destination) {
  try {
    const stats = await fs.lstat(destination).catch(() => null);
    if (stats) {
      if (stats.isSymbolicLink()) {
        const currentTarget = await fs.readlink(destination);
        if (path.resolve(path.dirname(destination), currentTarget) === source) {
          return;
        }
      }
      await fs.rm(destination, { force: true });
    }

    const relativeSource = path.relative(path.dirname(destination), source);
    await fs.symlink(relativeSource, destination, 'file');
  } catch (error) {
    if (error && (error.code === 'EPERM' || error.code === 'EEXIST')) {
      const contents = await fs.readFile(source);
      await fs.writeFile(destination, contents);
      await fs.chmod(destination, 0o755);
      return;
    }
    throw error;
  }
}

async function main() {
  await ensureTargetDir();
  const commands = ['tsc', 'tsserver', 'vitest'];
  await Promise.all(
    commands.map(async (command) => {
      const source = path.join(sourceDir, command);
      try {
        await fs.access(source);
      } catch (error) {
        if (error && error.code === 'ENOENT') {
          return;
        }
        throw error;
      }
      const destination = path.join(targetDir, command);
      await createLink(source, destination);
    })
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
