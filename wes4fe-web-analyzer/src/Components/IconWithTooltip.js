import React, { useState } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faInfoCircle } from '@fortawesome/free-solid-svg-icons';
import '../Styles/IconWithTooltip.css';

const IconWithTooltip = ({ text }) => {
    const [isHovered, setIsHovered] = useState(false);

    return (
        <div
            className="icon-container"
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={() => setIsHovered(false)}
        >
            <FontAwesomeIcon icon={faInfoCircle} />
            {isHovered && <div className="tooltip">{text}</div>}
        </div>
    );
};

export default IconWithTooltip;
