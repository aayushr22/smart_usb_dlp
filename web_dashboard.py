#!/usr/bin/env python3
"""
Smart USB DLP System - Web Dashboard
Real-time monitoring and threat visualization dashboard
"""

import os
import json
import sqlite3
import pandas as pd
import plotly.graph_objs as go
import plotly.express as px
from datetime import datetime, timedelta
import dash
from dash import dcc, html, Input, Output, State, callback_context
import dash_bootstrap_components as dbc
import dash_daq as daq
from flask import Flask
import logging

# Import our modules
try:
    from usb_config import config
    from usb_models import USBDatabase
    from usb_ml_model import USBMLModel
except ImportError:
    # Fallback for development
    print("Warning: Could not import USB modules. Using mock data.")
    config = None

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask server
server = Flask(__name__)
server.secret_key = os.environ.get('SECRET_KEY', 'usb-dlp-dashboard-secret')

# Initialize Dash app
app = dash.Dash(__name__, 
                server=server,
                external_stylesheets=[dbc.themes.BOOTSTRAP, dbc.icons.FONT_AWESOME],
                suppress_callback_exceptions=True)

# Global variables
db = None
ml_model = None

def init_components():
    """Initialize database and ML model components"""
    global db, ml_model
    try:
        db = USBDatabase()
        ml_model = USBMLModel()
        logger.info("Dashboard components initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize components: {e}")
        # Create mock components for development
        db = MockDatabase()
        ml_model = MockMLModel()

def get_threat_summary():
    """Get threat summary statistics"""
    try:
        if db:
            threats_df = db.get_threat_detections(days=7)
            return {
                'total_threats': len(threats_df),
                'critical_threats': len(threats_df[threats_df['risk_level'] == 'CRITICAL']),
                'high_threats': len(threats_df[threats_df['risk_level'] == 'HIGH']),
                'medium_threats': len(threats_df[threats_df['risk_level'] == 'MEDIUM']),
                'low_threats': len(threats_df[threats_df['risk_level'] == 'LOW'])
            }
    except Exception as e:
        logger.error(f"Error getting threat summary: {e}")
    
    return {
        'total_threats': 0,
        'critical_threats': 0,
        'high_threats': 0,
        'medium_threats': 0,
        'low_threats': 0
    }

def create_threat_timeline():
    """Create threat timeline chart"""
    try:
        if db:
            threats_df = db.get_threat_detections(days=30)
            if not threats_df.empty:
                threats_df['timestamp'] = pd.to_datetime(threats_df['timestamp'])
                threats_df['date'] = threats_df['timestamp'].dt.date
                
                timeline = threats_df.groupby(['date', 'risk_level']).size().reset_index(name='count')
                
                fig = px.line(timeline, x='date', y='count', color='risk_level',
                             title='Threat Timeline (Last 30 Days)',
                             color_discrete_map={
                                 'CRITICAL': '#FF0000',
                                 'HIGH': '#FF8C00',
                                 'MEDIUM': '#FFD700',
                                 'LOW': '#32CD32'
                             })
                
                fig.update_layout(
                    xaxis_title="Date",
                    yaxis_title="Number of Threats",
                    legend_title="Risk Level",
                    height=400
                )
                
                return fig
    except Exception as e:
        logger.error(f"Error creating threat timeline: {e}")
    
    # Return empty figure if no data
    return go.Figure().add_annotation(
        text="No threat data available",
        xref="paper", yref="paper",
        x=0.5, y=0.5, showarrow=False
    )

def create_user_activity_chart():
    """Create user activity chart"""
    try:
        if db:
            user_stats = db.get_user_statistics()
            if user_stats.get('top_users'):
                users_data = pd.DataFrame(user_stats['top_users'], 
                                        columns=['user', 'activity_count', 'total_bytes'])
                
                fig = px.bar(users_data, x='user', y='activity_count',
                           title='Top 10 Users by Activity',
                           color='total_bytes',
                           color_continuous_scale='Viridis')
                
                fig.update_layout(
                    xaxis_title="User",
                    yaxis_title="Activity Count",
                    height=400
                )
                
                return fig
    except Exception as e:
        logger.error(f"Error creating user activity chart: {e}")
    
    return go.Figure().add_annotation(
        text="No user data available",
        xref="paper", yref="paper",
        x=0.5, y=0.5, showarrow=False
    )

def create_device_risk_chart():
    """Create device risk distribution chart"""
    try:
        if db:
            device_stats = db.get_device_statistics()
            if device_stats.get('devices_by_risk'):
                risk_data = pd.DataFrame(list(device_stats['devices_by_risk'].items()),
                                       columns=['risk_level', 'count'])
                
                colors = {
                    'CRITICAL': '#FF0000',
                    'HIGH': '#FF8C00',
                    'MEDIUM': '#FFD700',
                    'LOW': '#32CD32'
                }
                
                fig = px.pie(risk_data, values='count', names='risk_level',
                           title='Device Risk Distribution',
                           color='risk_level',
                           color_discrete_map=colors)
                
                fig.update_layout(height=400)
                
                return fig
    except Exception as e:
        logger.error(f"Error creating device risk chart: {e}")
    
    return go.Figure().add_annotation(
        text="No device data available",
        xref="paper", yref="paper",
        x=0.5, y=0.5, showarrow=False
    )

# Dashboard Layout
app.layout = dbc.Container([
    dbc.Row([
        dbc.Col([
            html.H1("USB DLP Threat Detection Dashboard", className="text-center mb-4"),
            html.Hr()
        ])
    ]),
    
    # Status Cards
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("Critical Threats", className="card-title text-danger"),
                    html.H2(id="critical-count", className="text-danger")
                ])
            ])
        ], width=3),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("High Threats", className="card-title text-warning"),
                    html.H2(id="high-count", className="text-warning")
                ])
            ])
        ], width=3),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("Medium Threats", className="card-title text-info"),
                    html.H2(id="medium-count", className="text-info")
                ])
            ])
        ], width=3),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("Total Threats", className="card-title"),
                    html.H2(id="total-count")
                ])
            ])
        ], width=3)
    ], className="mb-4"),
    
    # Charts Row 1
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    dcc.Graph(id="threat-timeline")
                ])
            ])
        ], width=8),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    dcc.Graph(id="device-risk-chart")
                ])
            ])
        ], width=4)
    ], className="mb-4"),
    
    # Charts Row 2
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    dcc.Graph(id="user-activity-chart")
                ])
            ])
        ], width=12)
    ], className="mb-4"),
    
    # Real-time Alerts Section
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Recent Threat Alerts"),
                dbc.CardBody([
                    html.Div(id="alert-list")
                ])
            ])
        ], width=8),
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("System Status"),
                dbc.CardBody([
                    html.Div([
                        html.H5("ML Model Status"),
                        daq.Indicator(
                            id="ml-status-indicator",
                            color="green",
                            value=True,
                            label="Online"
                        ),
                        html.Hr(),
                        html.H5("Database Status"),
                        daq.Indicator(
                            id="db-status-indicator",
                            color="green",
                            value=True,
                            label="Connected"
                        ),
                        html.Hr(),
                        html.H5("Last Update"),
                        html.P(id="last-update")
                    ])
                ])
            ])
        ], width=4)
    ], className="mb-4"),
    
    # Configuration Panel
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Configuration"),
                dbc.CardBody([
                    dbc.Row([
                        dbc.Col([
                            html.Label("Risk Score Threshold"),
                            dcc.Slider(
                                id="risk-threshold-slider",
                                min=0,
                                max=10,
                                step=0.1,
                                value=5.0,
                                marks={i: str(i) for i in range(11)},
                                tooltip={"placement": "bottom", "always_visible": True}
                            )
                        ], width=6),
                        dbc.Col([
                            html.Label("Alert Notifications"),
                            dbc.Checklist(
                                id="alert-options",
                                options=[
                                    {"label": "Email Alerts", "value": "email"},
                                    {"label": "Slack Notifications", "value": "slack"},
                                    {"label": "SMS Alerts", "value": "sms"}
                                ],
                                value=["email"]
                            )
                        ], width=6)
                    ])
                ])
            ])
        ])
    ], className="mb-4"),
    
    # Auto-refresh component
    dcc.Interval(
        id='interval-component',
        interval=30*1000,  # Update every 30 seconds
        n_intervals=0
    )
], fluid=True)

# Callbacks
@app.callback(
    [Output('critical-count', 'children'),
     Output('high-count', 'children'),
     Output('medium-count', 'children'),
     Output('total-count', 'children'),
     Output('threat-timeline', 'figure'),
     Output('user-activity-chart', 'figure'),
     Output('device-risk-chart', 'figure'),
     Output('alert-list', 'children'),
     Output('last-update', 'children')],
    [Input('interval-component', 'n_intervals')]
)
def update_dashboard(n):
    """Update all dashboard components"""
    try:
        # Get threat summary
        threat_summary = get_threat_summary()
        
        # Create charts
        timeline_fig = create_threat_timeline()
        user_activity_fig = create_user_activity_chart()
        device_risk_fig = create_device_risk_chart()
        
        # Get recent alerts
        alert_list = get_recent_alerts()
        
        # Update timestamp
        last_update = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return (
            threat_summary['critical_threats'],
            threat_summary['high_threats'],
            threat_summary['medium_threats'],
            threat_summary['total_threats'],
            timeline_fig,
            user_activity_fig,
            device_risk_fig,
            alert_list,
            last_update
        )
    except Exception as e:
        logger.error(f"Error updating dashboard: {e}")
        return "Error", "Error", "Error", "Error", go.Figure(), go.Figure(), go.Figure(), "Error loading alerts", "Error"

def get_recent_alerts():
    """Get recent threat alerts"""
    try:
        if db:
            threats_df = db.get_threat_detections(days=1)
            if not threats_df.empty:
                # Sort by timestamp descending
                threats_df = threats_df.sort_values('timestamp', ascending=False)
                
                alerts = []
                for _, threat in threats_df.head(10).iterrows():
                    color = {
                        'CRITICAL': 'danger',
                        'HIGH': 'warning',
                        'MEDIUM': 'info',
                        'LOW': 'light'
                    }.get(threat['risk_level'], 'light')
                    
                    alert = dbc.Alert([
                        html.H6(f"{threat['risk_level']} Risk Detected", className="alert-heading"),
                        html.P(f"User: {threat['user']} | Device: {threat['device_id']}"),
                        html.P(f"Score: {threat['risk_score']:.2f} | Time: {threat['timestamp']}")
                    ], color=color, className="mb-2")
                    
                    alerts.append(alert)
                
                return alerts
    except Exception as e:
        logger.error(f"Error getting recent alerts: {e}")
    
    return [html.P("No recent alerts")]

# Mock classes for development
class MockDatabase:
    def get_threat_detections(self, days=7):
        return pd.DataFrame()
    
    def get_user_statistics(self):
        return {'top_users': []}
    
    def get_device_statistics(self):
        return {'devices_by_risk': {}}

class MockMLModel:
    def get_model_stats(self):
        return {'model_status': 'Mock Mode'}

# Configuration callback
@app.callback(
    Output('ml-status-indicator', 'color'),
    [Input('interval-component', 'n_intervals')]
)
def update_ml_status(n):
    """Update ML model status indicator"""
    try:
        if ml_model:
            stats = ml_model.get_model_stats()
            if 'Ready' in stats.get('model_status', ''):
                return 'green'
            else:
                return 'orange'
    except:
        pass
    return 'red'

@app.callback(
    Output('db-status-indicator', 'color'),
    [Input('interval-component', 'n_intervals')]
)
def update_db_status(n):
    """Update database status indicator"""
    try:
        if db:
            # Simple connection test
            db.get_user_statistics()
            return 'green'
    except:
        pass
    return 'red'

# Initialize components
init_components()

if __name__ == '__main__':
    app.run_server(debug=True, host='0.0.0.0', port=8050)