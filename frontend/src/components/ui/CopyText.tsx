import { useCallback } from 'react';
import { message } from 'antd';
import { CopyOutlined } from '@ant-design/icons';

import { copyToClipboard } from '@/utils/clipboard';

interface CopyTextProps {
  text: string;
  display?: string;
}

// Click-to-copy text with an antd toast confirmation. `display` lets the
// caller show a shortened form while copying the full value.
export default function CopyText({ text, display }: CopyTextProps) {
  const [messageApi, contextHolder] = message.useMessage();

  const onCopy = useCallback(async () => {
    const ok = await copyToClipboard(text);
    if (ok) {
      void messageApi.success('Copied to clipboard');
    } else {
      void messageApi.error('Copy failed');
    }
  }, [messageApi, text]);

  return (
    <span
      className="copy-text"
      role="button"
      tabIndex={0}
      title="Click to copy"
      onClick={() => void onCopy()}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          void onCopy();
        }
      }}
    >
      {contextHolder}
      <span className="copy-text-value">{display ?? text}</span>
      <CopyOutlined className="copy-text-icon" />
    </span>
  );
}
