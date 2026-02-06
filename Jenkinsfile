pipeline {
  agent any

  environment {
    CONTAINER_JENKINS_NAME = "jenkins-blueocean"
    TERRASCAN_IMAGE = "tenable/terrascan:latest"

    // Si querés forzar un directorio fijo, ponelo acá (si existe):
    // Ej: "terraform/aws"
    TERRAFORM_DIR_HINT = ""
  }

  stages {

    stage('Checkout') {
      steps { checkout scm }
    }

    stage('Diagnóstico (estructura + TF)') {
      steps {
        sh '''
          set -eu
          echo "WORKSPACE=$WORKSPACE"
          echo "=== root ls ==="
          ls -la

          echo "=== buscando terraform dirs (hasta profundidad 4) ==="
          find . -maxdepth 4 -type d -iname "terraform" -o -iname "infra" -o -iname "infrastructure" | head -200 || true

          echo "=== primeros .tf (hasta 80) ==="
          find . -type f -name "*.tf" | head -n 80 || true

          echo "=== primeros resources encontrados (hasta 80) ==="
          grep -R --line-number 'resource "' . 2>/dev/null | head -n 80 || true
        '''
      }
    }

    stage('Seleccionar directorio Terraform') {
      steps {
        sh '''
          set -eu
          mkdir -p results

          # 1) Si el usuario dio un hint y existe, úsalo
          if [ -n "${TERRAFORM_DIR_HINT:-}" ] && [ -d "$TERRAFORM_DIR_HINT" ]; then
            echo "$TERRAFORM_DIR_HINT" > results/target_dir.txt
            echo "TARGET_DIR (hint)=$TERRAFORM_DIR_HINT"
            exit 0
          fi

          # 2) Elegir un directorio que tenga recursos (no solo variables.tf)
          #    Tomamos el primer archivo .tf que contenga 'resource "' y usamos su carpeta.
          RES_FILE="$(grep -R --files-with-matches 'resource "' . 2>/dev/null | head -n 1 || true)"
          if [ -n "$RES_FILE" ]; then
            TARGET_DIR="$(dirname "$RES_FILE")"
            echo "$TARGET_DIR" > results/target_dir.txt
            echo "TARGET_DIR (resource)=$TARGET_DIR"
            exit 0
          fi

          # 3) Fallback: primer .tf disponible
          ANY_TF="$(find . -type f -name '*.tf' | head -n 1 || true)"
          if [ -n "$ANY_TF" ]; then
            TARGET_DIR="$(dirname "$ANY_TF")"
            echo "$TARGET_DIR" > results/target_dir.txt
            echo "TARGET_DIR (fallback)=$TARGET_DIR"
            exit 0
          fi

          echo "No se encontraron archivos .tf en el repo. Abortando."
          exit 2
        '''
      }
    }

    stage('Terrascan (JSON + JUnit)') {
      steps {
        sh '''
          set -eu
          TARGET_DIR="$(cat results/target_dir.txt)"
          echo "Escaneando TARGET_DIR=$TARGET_DIR"

          # Sanity check dentro del contenedor Jenkins
          test -d "$TARGET_DIR" || (echo "No existe TARGET_DIR dentro del workspace: $TARGET_DIR" && exit 2)

          # Terrascan corre como contenedor del host, así que heredamos volúmenes del contenedor Jenkins
          docker run --rm \
            --volumes-from "$CONTAINER_JENKINS_NAME" \
            -w "$WORKSPACE" \
            "$TERRASCAN_IMAGE" scan -i terraform -d "$TARGET_DIR" \
            --output json > results/terrascan.json || true

          docker run --rm \
            --volumes-from "$CONTAINER_JENKINS_NAME" \
            -w "$WORKSPACE" \
            "$TERRASCAN_IMAGE" scan -i terraform -d "$TARGET_DIR" \
            --output junit-xml > results/terrascan.junit.xml || true

          # Asegurarnos que existen
          test -s results/terrascan.json || (echo "No se generó results/terrascan.json" && exit 2)
          test -s results/terrascan.junit.xml || (echo "No se generó results/terrascan.junit.xml" && exit 2)

          echo "=== Terrascan summary (raw json head) ==="
          head -n 50 results/terrascan.json || true
        '''
      }
    }

    stage('Reporte claro (findings + archivo + línea)') {
      steps {
        sh '''
          set -eu

          # Parseo con Python en contenedor (sin python en el agent)
          docker run --rm \
            --volumes-from "$CONTAINER_JENKINS_NAME" \
            -w "$WORKSPACE" \
            python:3.12-alpine python - <<'PY'
import json
from collections import Counter

data = json.load(open("results/terrascan.json", "r", encoding="utf-8"))
results = data.get("results") or {}

scan_errors = results.get("scan_errors") or []
violations = results.get("violations") or []

summary = results.get("scan_summary") or {}
print("=== SCAN SUMMARY ===")
for k in ["file/folder","iac_type","policies_validated","violated_policies","low","medium","high"]:
    print(f"{k}: {summary.get(k)}")

if scan_errors:
    print("\n=== SCAN ERRORS (info) ===")
    # mostrarmos solo 5 para no llenar
    for e in scan_errors[:5]:
        print(f"- {e.get('iac_type')}: {e.get('errMsg')}")

# Cuando Terrascan no evaluó policies, violations suele ser None y policies_validated=0
if not violations:
    print("\n=== VIOLATIONS ===")
    print("No hay violaciones (o no se evaluaron policies).")
    print("Si policies_validated=0, el directorio puede tener solo variables/outputs o no hay reglas aplicables.")
    raise SystemExit(0)

print("\n=== TOP VIOLATIONS (hasta 15) ===")
# Conteo por severidad
sev = Counter((v.get("severity") or "UNKNOWN").upper() for v in violations)
print("Severidades:", dict(sev))

for v in violations[:15]:
    loc = v.get("location") or {}
    rid = v.get("rule_id")
    sev = (v.get("severity") or "").upper()
    desc = v.get("description") or v.get("rule_name") or ""
    print(f"\n- rule_id: {rid}")
    print(f"  severity: {sev}")
    print(f"  description: {desc}")
    print(f"  file: {loc.get('file')}")
    print(f"  line: {loc.get('line')}")

print("\nTIP: usa 'file' y 'line' para ir directo al .tf a remediar.")
PY
        '''
      }
    }

    stage('Security Gate (opcional: falla si HIGH/CRITICAL)') {
      steps {
        sh '''
          set -eu

          docker run --rm \
            --volumes-from "$CONTAINER_JENKINS_NAME" \
            -w "$WORKSPACE" \
            python:3.12-alpine python - <<'PY'
import json, sys
data = json.load(open("results/terrascan.json", "r", encoding="utf-8"))
violations = ((data.get("results") or {}).get("violations")) or []
high = [v for v in violations if (v.get("severity") or "").upper() == "HIGH"]
crit = [v for v in violations if (v.get("severity") or "").upper() == "CRITICAL"]

print(f"Gate check -> HIGH: {len(high)} | CRITICAL: {len(crit)}")

# Si no hubo evaluación, no bloqueamos (para que puedas ver diagnóstico)
summary = (data.get("results") or {}).get("scan_summary") or {}
if (summary.get("policies_validated") or 0) == 0:
    print("Gate: policies_validated=0, no bloqueo el build. Revisa el TARGET_DIR.")
    sys.exit(0)

if crit or high:
    print("❌ Gate failed (HIGH/CRITICAL).")
    for v in (crit + high)[:10]:
        loc = v.get("location") or {}
        print(f"- {v.get('rule_id')} | {v.get('severity')} | {v.get('description')}")
        print(f"  file: {loc.get('file')} line: {loc.get('line')}")
    sys.exit(1)

print("✅ Gate passed.")
PY
        '''
      }
    }
  }

  post {
    always {
      archiveArtifacts artifacts: 'results/*', fingerprint: true
      junit testResults: 'results/terrascan.junit.xml', allowEmptyResults: true
    }
    failure {
      echo '❌ Pipeline falló (probablemente por gate HIGH/CRITICAL o falta de policies). Mira results/terrascan.json y el stage "Reporte claro".'
    }
  }
}
