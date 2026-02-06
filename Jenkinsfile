pipeline {
  agent any

  environment {
    JENKINS_CONTAINER = "jenkins-blueocean"
    TERRASCAN_IMAGE  = "tenable/terrascan:latest"
  }

  stages {
    stage('Verificar checkout') {
      steps {
        sh '''
          set -eu
          echo "WORKSPACE=$WORKSPACE"
          echo "=== ls root ==="
          ls -la
    
          echo "=== git status ==="
          git status || true
    
          echo "=== git remote/branch ==="
          git remote -v || true
          git branch -a || true
    
          echo "=== buscar terraform ==="
          find . -maxdepth 4 -type d -name terraform -print || true
    
          echo "=== buscar .tf ==="
          find . -type f -name "*.tf" | head -n 50 || true
    
          echo "=== buscar 'resource \"' ==="
          grep -R --line-number 'resource "' . 2>/dev/null | head -n 50 || true
        '''
      }
    }
    
    stage('Detectar mejor directorio Terraform (auto)') {
      steps {
        sh '''
          set -eu
          mkdir -p results

          # Detecta el mejor directorio (más recursos y con provider aws/azurerm/google)
          docker run --rm \
            --volumes-from "$JENKINS_CONTAINER" \
            -w "$WORKSPACE" \
            python:3.12-alpine python - <<'PY' > results/target_dir.txt
          import os, re
          from collections import defaultdict
          
          ROOT = "."
          tf_files = []
          for d, _, files in os.walk(ROOT):
              # evita vendor/.terraform para no ensuciar
              if "/.terraform" in d or d.endswith("/.terraform"):
                  continue
              for f in files:
                  if f.endswith(".tf"):
                      tf_files.append(os.path.join(d, f))
          
          if not tf_files:
              print("", end="")
              raise SystemExit(0)
          
          resource_re = re.compile(r'\\bresource\\s+"', re.IGNORECASE)
          provider_re = re.compile(r'\\bprovider\\s+"(aws|azurerm|google)"', re.IGNORECASE)
          aws_re = re.compile(r'\\baws_', re.IGNORECASE)
          az_re  = re.compile(r'\\bazurerm_', re.IGNORECASE)
          gcp_re = re.compile(r'\\bgoogle_', re.IGNORECASE)
          
          score = defaultdict(int)
          has_cloud_hint = defaultdict(bool)
          
          for path in tf_files:
              try:
                  txt = open(path, "r", encoding="utf-8", errors="ignore").read()
              except:
                  continue
          
              dirp = os.path.dirname(path)
              rcount = len(resource_re.findall(txt))
              score[dirp] += rcount
          
              # señales de cloud “real”
              if provider_re.search(txt) or aws_re.search(txt) or az_re.search(txt) or gcp_re.search(txt):
                  has_cloud_hint[dirp] = True
          
          # elegir el dir con:
          # - cloud hint (aws/azurerm/google) si existe
          # - mayor cantidad de resources
          candidates = [d for d in score if score[d] > 0]
          cloud_candidates = [d for d in candidates if has_cloud_hint[d]]
          
          pick_from = cloud_candidates if cloud_candidates else candidates
          best = sorted(pick_from, key=lambda d: score[d], reverse=True)[0] if pick_from else ""
          
          print(best, end="")
          PY

          TARGET_DIR="$(cat results/target_dir.txt || true)"
          echo "TARGET_DIR elegido: ${TARGET_DIR:-<vacio>}"

          if [ -z "${TARGET_DIR:-}" ]; then
            echo "No se encontraron recursos Terraform (resource \\"\\") en el repo."
            echo "Abortando."
            exit 2
          fi

          # Validación dentro del workspace
          test -d "$TARGET_DIR" || (echo "TARGET_DIR no existe en workspace: $TARGET_DIR" && exit 2)

          echo "$TARGET_DIR" > results/target_dir.txt
        '''
      }
    }

    stage('Terrascan (JSON + JUnit)') {
      steps {
        sh '''
          set -eu
          TARGET_DIR="$(cat results/target_dir.txt)"
          echo "Escaneando con Terrascan: $TARGET_DIR"

          # Genera reportes. No cortamos por findings para poder ver resultados.
          docker run --rm \
            --volumes-from "$JENKINS_CONTAINER" \
            -w "$WORKSPACE" \
            "$TERRASCAN_IMAGE" scan -i terraform -d "$TARGET_DIR" \
            --output json > results/terrascan.json || true

          docker run --rm \
            --volumes-from "$JENKINS_CONTAINER" \
            -w "$WORKSPACE" \
            "$TERRASCAN_IMAGE" scan -i terraform -d "$TARGET_DIR" \
            --output junit-xml > results/terrascan.junit.xml || true

          test -s results/terrascan.json || (echo "No se generó results/terrascan.json" && exit 2)
          test -s results/terrascan.junit.xml || (echo "No se generó results/terrascan.junit.xml" && exit 2)
        '''
      }
    }

    stage('Mostrar vulnerabilidades (archivo + línea)') {
      steps {
        sh '''
          set -eu

          docker run --rm \
            --volumes-from "$JENKINS_CONTAINER" \
            -w "$WORKSPACE" \
            python:3.12-alpine python - <<'PY'
            import json
            data = json.load(open("results/terrascan.json", "r", encoding="utf-8"))
            res = data.get("results") or {}
            summary = res.get("scan_summary") or {}
            
            print("=== SUMMARY ===")
            for k in ["file/folder","iac_type","policies_validated","violated_policies","low","medium","high"]:
                print(f"{k}: {summary.get(k)}")
            
            violations = res.get("violations") or []
            if not violations:
                print("\\nNo hay violaciones. Si policies_validated=0, el dir escaneado no tiene recursos evaluables.")
            else:
                print("\\n=== TOP VIOLATIONS (hasta 20) ===")
                for v in violations[:20]:
                    loc = v.get("location") or {}
                    print(f"- {v.get('rule_id')} | {v.get('severity')} | {v.get('description')}")
                    print(f"  file: {loc.get('file')}  line: {loc.get('line')}")
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
  }
}
