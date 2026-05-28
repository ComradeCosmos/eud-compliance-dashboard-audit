import numpy as np
import torch
import torch.nn as nn
from typing import Dict, List, Tuple

class ScoreDriftLSTM(nn.Module):
    """
    LSTM-based time-series forecasting model for EUD device compliance scores.
    Processes a 90-day trajectory of daily scores to predict compliance levels at 7/14/30-day horizons.
    """
    def __init__(self, input_dim: int = 1, hidden_dim: int = 64, num_layers: int = 2, output_dim: int = 3):
        super(ScoreDriftLSTM, self).__init__()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        
        # LSTM core network
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True, dropout=0.2)
        
        # Fully connected projection output layer (predicts 3 values: 7-day, 14-day, and 30-day forecast)
        self.fc = nn.Linear(hidden_dim, output_dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # Initialize hidden and cell states
        h0 = torch.zeros(self.num_layers, x.size(0), self.hidden_dim).to(x.device)
        c0 = torch.zeros(self.num_layers, x.size(0), self.hidden_dim).to(x.device)
        
        out, _ = self.lstm(x, (h0, c0))
        
        # Map last LSTM step output to forecast horizon
        predictions = self.fc(out[:, -1, :])
        return predictions

class DriftPredictorService:
    def __init__(self, model_path: str = None):
        self.model = ScoreDriftLSTM()
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        self.model.eval()
        
        if model_path:
            try:
                self.model.load_state_dict(torch.load(model_path, map_location=self.device))
            except Exception as e:
                print(f"Warning: Model state load failed, utilizing unit initialized weights. Details: {e}")

    def predict_drift(self, score_history_90_days: List[float]) -> Dict[str, float]:
        """
        Takes exactly 90 daily risk score records, processes them through the LSTM network,
        and returns predicted scores at 7-day, 14-day, and 30-day benchmarks.
        """
        if len(score_history_90_days) != 90:
            raise ValueError(f"Time-series input must consist of exactly 90 steps. Got {len(score_history_90_days)}")

        # Normalize score bounds to [0.0, 1.0] for training/inference stability
        normalized_data = np.array(score_history_90_days, dtype=np.float32) / 100.0
        input_tensor = torch.tensor(normalized_data).reshape(1, 90, 1).to(self.device)

        with torch.no_grad():
            raw_predictions = self.model(input_tensor).squeeze(0).cpu().numpy()
            
        # Denormalize predictions back to 0-100 scale, bounding mathematically
        denorm_preds = np.clip(raw_predictions * 100.0, 0.0, 100.0)
        
        return {
            "forecast_7_days": float(round(denorm_preds[0], 2)),
            "forecast_14_days": float(round(denorm_preds[1], 2)),
            "forecast_30_days": float(round(denorm_preds[2], 2))
        }
