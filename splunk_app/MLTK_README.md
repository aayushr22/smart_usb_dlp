# Splunk MLTK Integration
using Splunk Machine Learning Toolkit (MLTK) with the Smart USB DLP System.

## Data Export
- The system exports recent USB events to `data/lookups/usb_events_for_splunk.csv`.
- Configure Splunk to monitor this file as a lookup or data input.

## Using MLTK
- Use the exported CSV as a dataset in Splunk MLTK for training, scoring, and visualization.
- Example fields: timestamp, event_type, device_id, manufacturer, model, serial_number, action, score, bytes_transferred.

## Custom Algorithms
- Place any custom Python algorithms for MLTK in `splunk_app/bin/`.
- See Splunk MLTK documentation for details: https://docs.splunk.com/Documentation/MLApp