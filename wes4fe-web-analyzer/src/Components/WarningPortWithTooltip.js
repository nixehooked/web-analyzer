import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faWarning } from '@fortawesome/free-solid-svg-icons';
import '../Styles/IconWithTooltip.css';

const WarningPortWithTooltip = ({ text }) => {
    const [isHovered, setIsHovered] = useState(false);

    return (
        <div
            className="icon-container"
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={() => setIsHovered(false)}
        >
            <FontAwesomeIcon icon={faWarning} />
            {isHovered && <div className="tooltip">{text}</div>}
        </div>
    );
};

export default WarningPortWithTooltip;