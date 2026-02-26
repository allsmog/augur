import { fileURLToPath } from "node:url";
import { dirname } from "node:path";
export const augurRoot = dirname(fileURLToPath(import.meta.url));
