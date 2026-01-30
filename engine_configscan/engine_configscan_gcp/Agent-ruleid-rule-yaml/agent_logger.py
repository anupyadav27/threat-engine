"""
Centralized logging for all GCP agents.

Usage:
    from agent_logger import get_logger
    
    logger = get_logger('agent1')
    logger.info("Processing...")
"""

import logging
import os
from datetime import datetime


def get_logger(agent_name: str) -> logging.Logger:
    """
    Get logger for an agent.
    
    Args:
        agent_name: Name of the agent (e.g., 'agent1', 'agent2')
    
    Returns:
        Configured logger
    """
    # Create logs directory
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)
    
    # Create logger
    logger = logging.getLogger(agent_name)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    
    # File handler - timestamped
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(log_dir, f'{agent_name}_{timestamp}.log')
    
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter(
        '%(asctime)s [%(name)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(fh)
    
    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(
        '%(levelname)s: %(message)s'
    ))
    logger.addHandler(ch)
    
    # Also log to master log
    master_log = os.path.join(log_dir, 'pipeline.log')
    mh = logging.FileHandler(master_log)
    mh.setLevel(logging.INFO)
    mh.setFormatter(logging.Formatter(
        '%(asctime)s [%(name)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(mh)
    
    logger.info(f"Logger initialized - {agent_name}")
    logger.info(f"Log file: {log_file}")
    
    return logger

