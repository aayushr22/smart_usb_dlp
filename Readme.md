# Smart USB Data Loss Prevention System
**Splunk Build-a-thon AI/ML Track-4 Submission**

## Problem Statement & Solution Overview

### Problem Statement
**Unusual Volume of Bytes Written to USB per Device - Automated Data Exfiltration Detection**

Data theft via USB devices remains one of the most common and dangerous threats, yet most organizations lack real-time detection capabilities. Traditional DLP solutions are expensive, complex, and often generate too many false positives. There's a gap in affordable, ML-driven solutions that can automatically distinguish between legitimate business use and potential data theft.

### Solution Overview
The Smart USB Data Loss Prevention System is a lightweight, ML-powered Splunk app that automatically learns normal USB usage patterns for each user and device, then detects suspicious data transfer activities in real-time. This fills the major gap between basic logging and expensive enterprise DLP solutions.

**Key Innovation:** Instead of relying on static rules, the system builds dynamic behavioral baselines and detects anomalies that indicate potential data theft attempts.

## Machine Learning Approach

### Model Type
- **Primary Model:** Density-Based Spatial Clustering (DBSCAN) for anomaly detection
- **Secondary Model:** Isolation Forest for outlier detection
- **Approach:** Unsupervised learning with statistical baseline establishment

### Key Features Extracted
1. **Bytes written per session** - Primary indicator of data volume
2. **Time-based patterns** - Working hours vs. off-hours activity
3. **Device characteristics** - USB device type, capacity, manufacturer
4. **User behavior patterns** - Historical usage patterns per user
5. **Session duration** - Time spent transferring data
6. **File type distribution** - Types of files being transferred

### Model Selection Justification
- **DBSCAN**: Excellent for identifying clusters of normal behavior and flagging outliers
- **Isolation Forest**: Effective at detecting anomalous data transfer volumes without requiring labeled training data
- **Unsupervised approach**: No need for historical breach data, learns from normal operations

## Support & Contact
For technical support or questions about this project, please contact the development team : aayushr2201@gmail.com, dadwalkhushi05@gmail.com.

---