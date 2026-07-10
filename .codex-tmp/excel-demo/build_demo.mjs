import fs from "node:fs/promises";
import path from "node:path";
import { SpreadsheetFile, Workbook } from "@oai/artifact-tool";

const outputDir = path.resolve(process.cwd(), "..", "..", "outputs", "excel-demo-20260706");
await fs.mkdir(outputDir, { recursive: true });

const workbook = Workbook.create();
const sheet = workbook.worksheets.add("Demo");
sheet.showGridLines = false;

sheet.getRange("A1:D1").merge();
sheet.getRange("A1:D1").values = [["Excel-Demo von Codex"]];
sheet.getRange("A1:D1").format = {
  fill: "#1F4E78",
  font: { bold: true, color: "#FFFFFF", size: 16 },
  horizontalAlignment: "center",
};
sheet.getRange("A1:D1").format.rowHeight = 28;

sheet.getRange("A3:D6").values = [
  ["Position", "Menge", "Preis", "Summe"],
  ["VPN-Lizenz", 3, 12.5, null],
  ["Support", 2, 25, null],
  ["Setup", 1, 49, null],
];
sheet.getRange("D4").formulas = [["=B4*C4"]];
sheet.getRange("D4:D6").fillDown();

sheet.getRange("A3:D3").format = {
  fill: "#D9EAF7",
  font: { bold: true, color: "#17365D" },
  borders: { preset: "bottom", style: "thin", color: "#7F9DB9" },
};
sheet.getRange("A4:D6").format.borders = {
  insideHorizontal: { style: "thin", color: "#E6EEF5" },
};
sheet.getRange("B4:B6").format.numberFormat = "#,##0";
sheet.getRange("C4:D6").format.numberFormat = '"€"#,##0.00';
sheet.getRange("B4:D7").format.horizontalAlignment = "right";

sheet.getRange("C8:D8").values = [["Gesamt", null]];
sheet.getRange("D8").formulas = [["=SUM(D4:D6)"]];
sheet.getRange("C8:D8").format = {
  fill: "#E2F0D9",
  font: { bold: true },
  borders: { preset: "outside", style: "thin", color: "#70AD47" },
};
sheet.getRange("D8").format.numberFormat = '"€"#,##0.00';

sheet.getRange("A10:D10").merge();
sheet.getRange("A10:D10").values = [["Diese Datei wurde automatisch erzeugt und enthält echte Excel-Formeln."]];
sheet.getRange("A10:D10").format = {
  fill: "#F7F9FB",
  font: { italic: true, color: "#666666" },
};

sheet.getRange("A:D").format.autofitColumns();
sheet.getRange("A1:D10").format.autofitRows();

const check = await workbook.inspect({
  kind: "table",
  range: "Demo!A1:D10",
  include: "values,formulas",
  tableMaxRows: 12,
  tableMaxCols: 6,
});
console.log(check.ndjson);

const errors = await workbook.inspect({
  kind: "match",
  searchTerm: "#REF!|#DIV/0!|#VALUE!|#NAME\\?|#N/A",
  options: { useRegex: true, maxResults: 300 },
  summary: "final formula error scan",
});
console.log(errors.ndjson);

const preview = await workbook.render({
  sheetName: "Demo",
  range: "A1:D10",
  scale: 2,
  format: "png",
});
await fs.writeFile(path.join(outputDir, "demo-preview.png"), new Uint8Array(await preview.arrayBuffer()));

const output = await SpreadsheetFile.exportXlsx(workbook);
await output.save(path.join(outputDir, "codex_excel_demo.xlsx"));
