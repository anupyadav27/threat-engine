"""
Centralized logging for all agents.
"""

import logging
import os
from datetime import datetime


def get_logger(agent_name: str) -> logging.Logger:
    """Get logger for an agent"""
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)
    
    logger = logging.getLogger(agent_name)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(log_dir, f'{agent_name}_{timestamp}.log')
    
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.INFO)
    fh.setFormatter(logging.Formatter(
        '%(asctime)s [%(name)s] %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(fh)
    
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    logger.addHandler(ch)
    
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
