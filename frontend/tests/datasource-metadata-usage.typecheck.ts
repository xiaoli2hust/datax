import { listDatasourceTables } from "../src/api/resources";
import type { DatasourceUsage } from "../src/types";

// Compile-only positive examples: the general datasource view may request either exact purpose.
const supportedUsages = [
  "SOURCE_USE",
  "TARGET_USE",
] as const satisfies readonly DatasourceUsage[];
for (const usage of supportedUsages) {
  void listDatasourceTables("00000000-0000-0000-0000-000000000000", { usage });
}

// Compile-only negative examples: an invented purpose and an omitted purpose must stay invalid.
void listDatasourceTables("00000000-0000-0000-0000-000000000000", {
  // @ts-expect-error READ_USE is not an API contract value.
  usage: "READ_USE",
});
// @ts-expect-error Metadata purpose is mandatory and must never silently default to SOURCE_USE.
void listDatasourceTables("00000000-0000-0000-0000-000000000000", {});
