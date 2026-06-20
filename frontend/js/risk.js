function exportRiskConfig() {
            const highWeight = document.getElementById("weight-high") ? parseFloat(document.getElementById("weight-high").value) : 10;
            const mediumWeight = document.getElementById("weight-medium") ? parseFloat(document.getElementById("weight-medium").value) : 5;
            const lowWeight = document.getElementById("weight-low") ? parseFloat(document.getElementById("weight-low").value) : 2;
            const env = document.getElementById("risk-env-select") ? document.getElementById("risk-env-select").value : "Production";

            const config = {
                environment: env,
                weights: {
                    HIGH: highWeight,
                    MEDIUM: mediumWeight,
                    LOW: lowWeight
                }
            };
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(config, null, 2));
            const downloadAnchor = document.createElement('a');
            downloadAnchor.setAttribute("href", dataStr);
            downloadAnchor.setAttribute("download", "risk_engine_config.json");
            document.body.appendChild(downloadAnchor);
            downloadAnchor.click();
            downloadAnchor.remove();
            alert("Risk Engine configuration exported successfully.");
        }

        function importRiskConfig(event) {
            const file = event.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = async function (e) {
                try {
                    const config = JSON.parse(e.target.result);
                    if (config.environment && document.getElementById("risk-env-select")) {
                        document.getElementById("risk-env-select").value = config.environment;
                    }
                    if (config.weights) {
                        if (config.weights.HIGH !== undefined && document.getElementById("weight-high")) {
                            document.getElementById("weight-high").value = config.weights.HIGH;
                        }
                        if (config.weights.MEDIUM !== undefined && document.getElementById("weight-medium")) {
                            document.getElementById("weight-medium").value = config.weights.MEDIUM;
                        }
                        if (config.weights.LOW !== undefined && document.getElementById("weight-low")) {
                            document.getElementById("weight-low").value = config.weights.LOW;
                        }
                    }
                    alert("Risk configuration loaded. Recalculating...");
                    await triggerRiskCalculation();
                    event.target.value = "";
                } catch (err) {
                    console.error(err);
                    alert("Failed to parse Risk Config file. Ensure it is a valid JSON configuration.");
                }
            };
            reader.readAsText(file);
        }

        