# AI-Driven-Cloud-Security-A-Zero-Trust-and-Automation-Approach-for-Hybrid-Environments
This project compares AI-driven anomaly detection (Isolation Forest) with a Traditional Rule-Based Detection system using the KDDTrain+ dataset for cybersecurity attack detection.
It evaluates performance based on Threat Detection Accuracy, False Positive Rate (FPR), Penetration Detection Rate (PDR), and Simulated Incident Response Time (MTTD).

📂 Project Structure
Dataset:

KDDTrain+.txt — Preprocessed KDD Cup 99 dataset version.

Code:

Python script that:

Loads and preprocesses the dataset

Trains Isolation Forest (AI model)

Implements a manual rule-based detection system

Evaluates both systems on Accuracy, FPR, and PDR

Simulates Incident Response Automation

⚙️ Requirements
Make sure you have the following Python libraries installed:

bash
Copy
Edit
pip install pandas numpy scikit-learn
🚀 How to Run
Clone the repository.

Place your dataset (KDDTrain+.txt) inside the project folder.

Update the file path if needed in the script:

python
Copy
Edit
df = pd.read_csv(r"C:\Users\HP\Desktop\KDDTrain+.txt", names=columns, sep=',')
(Change this to your correct path.)

Run the script:

bash
Copy
Edit
python your_script_name.py
📈 Evaluation Metrics

Metric	AI-Driven (Isolation Forest)	Traditional Rule-Based
Threat Detection Accuracy	93%	70%
False Positive Rate	<5%	15%
Penetration Detection Rate	92%	60%
Mean Time to Detect (MTTD)	<1 second	Several minutes
🛡 Key Highlights
AI-Based Detection uses IsolationForest to intelligently detect unseen attack patterns.

Rule-Based Detection applies simple threshold conditions (like src_bytes > 10000).

Automated Incident Response Simulation demonstrates real-world cloud security workflows.

Comparison Summary at the end shows the strength of AI-based security systems.

📚 References
KDD Cup 99 Dataset

Scikit-Learn Documentation

Research Inspiration:

"Transforming Incident Responses and Revolutionizing Defense Strategies Through AI-Powered Cybersecurity"

