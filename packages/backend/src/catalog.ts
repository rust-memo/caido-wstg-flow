import { WSTG_TSV } from "./catalog-data";
import type { WstgTestDTO } from "./types";

type CatalogTest = Omit<WstgTestDTO, "status" | "notes" | "candidateCount">;

export const WSTG_CATALOG: CatalogTest[] = WSTG_TSV.split("\n").flatMap(
  (line) => {
    if (line === "" || line.startsWith("#")) return [];
    const parts = line.split("\t");
    const category = parts[0];
    const id = parts[1];
    const name = parts[2];
    const reference = parts[3];
    const objectives = parts[4];
    if (
      category === undefined ||
      id === undefined ||
      name === undefined ||
      reference === undefined
    )
      return [];
    return [
      {
        category,
        id,
        name,
        commonName: name,
        reference,
        objectives: (objectives ?? "").replace(/\\n/g, "\n"),
      },
    ];
  },
);

export function validWstgId(value: string): boolean {
  return value === "" || WSTG_CATALOG.some((test) => test.id === value);
}
