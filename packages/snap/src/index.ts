import type {
  OnTransactionHandler,
  OnInstallHandler,
  OnHomePageHandler,
} from '@metamask/snaps-types';
import {
  heading,
  panel,
  text,
  divider,
  address,
  row,
} from '@metamask/snaps-sdk';
import {
  getHashDitResponse,
  parseTransactingValue,
  getNativeToken,
  authenticateHashDit,
  isEOA,
  addressPoisoningDetection,
} from './utils/utils';
import { extractPublicKeyFromSignature } from './utils/cryptography';

export const onInstall: OnInstallHandler = async () => {
  // Show install instructions and links
  await snap.request({
    method: 'snap_dialog',
    params: {
      type: 'alert',
      content: panel([
        heading('🛠️ Next Steps For Your Installation'),
        text('**Step 1**'),
        text(
          ' To ensure the most secure experience, please connect all your MetaMask accounts with the HashDit Snap.',
        ),
        text('**Step 2**'),
        text(
          'Sign the Hashdit Security message request. This is required to enable the HashDit API to enable a complete experience.',
        ),
        divider(),
        heading('🔗 Links'),
        text(
          'HashDit Snap Official Website: [Hashdit](https://www.hashdit.io/en/snap)',
        ),
        text(
          'Installation Guide: [Installation](https://hashdit.gitbook.io/hashdit-snap/usage/installing-hashdit-snap)',
        ),
        text(
          'How To Use Hashdit Snap: [Usage](https://hashdit.gitbook.io/hashdit-snap/usage/how-to-use-hashdit-snap)',
        ),
        text('Documentation: [Docs](https://hashdit.gitbook.io/hashdit-snap)'),
        text(
          'FAQ/Knowledge Base: [FAQ](https://hashdit.gitbook.io/hashdit-snap/information/faq-and-knowledge-base)',
        ),
        text(
          'MetaMask Store Page: [Snap Store](https://snaps.metamask.io/snap/npm/hashdit-snap-security/)',
        ),
        divider(),
        heading('Thank you for using HashDit Snap!'),
      ]),
    },
  });
};

// Handle outgoing transactions.
export const onTransaction: OnTransactionHandler = async ({
  transaction,
  transactionOrigin,
}) => {
  const accounts = await ethereum.request({
    method: 'eth_accounts',
    params: [],
  });
  // Transaction is a native token transfer if no contract bytecode found.
  if (await isEOA(transaction.to)) {
    const chainId = await ethereum.request({ method: 'eth_chainId' });
    // Check if chainId is undefined or null
    if (typeof chainId !== 'string') {
      const contentArray: any[] = [
        heading('HashDit Security Insights'),
        text(`Error: ChainId could not be retreived (${chainId})`),
      ];
      const content = panel(contentArray);
      return { content };
    }
    // Current chain is not supported (not BSC or ETH). Display not supported text.
    if (chainId !== '0x38' && chainId !== '0x1') {

      let contentArray: any[] = [];
      var urlRespData;

        const poisonResultArray = addressPoisoningDetection(accounts, [
          transaction.to,
        ]);
        if (poisonResultArray.length != 0) {
          contentArray = poisonResultArray;
        }

        urlRespData = await getHashDitResponse(
          'hashdit_snap_tx_api_url_detection',
          transactionOrigin,
        );
        contentArray.push(heading('URL Risk Information'));

        if (urlRespData.url_risk >= 2) {
          contentArray.push(text(`**${urlRespData.url_risk_title}**`));
        }
        contentArray.push(
          text(
            `The URL **${transactionOrigin}** has a risk of **${urlRespData.url_risk}**`,
          ),
          divider(),
        );
      

      const transactingValue = parseTransactingValue(transaction.value);
      const nativeToken = getNativeToken(chainId);

      contentArray.push(
        heading('Transfer Details'),
        text('Your Address'), text(transaction.from),
        text('Amount'), text(`${transactingValue} ${nativeToken}`),
        text('To'), text(transaction.to),
        divider(),
      );

      contentArray.push(
        text('HashDit Security Insights is not fully supported on this chain.'),
        text(
          'Currently we only support the **BSC Mainnet** and **ETH Mainnet**.',
        ),
      );

      const content = panel(contentArray);
      return { content };
    }
    // Current chain is supported (BSC or ETH). Display token transfer insights
    else {

      let contentArray: any[] = [];
      var respData;
      var urlRespData;
      
        const poisonResultArray = addressPoisoningDetection(accounts, [
          transaction.to,
        ]);
        if (poisonResultArray.length != 0) {
          contentArray = poisonResultArray;
        }

        respData = await getHashDitResponse(
          'internal_address_lables_tags',

          transactionOrigin,
          transaction,
          chainId,
        );
        urlRespData = await getHashDitResponse(
          'hashdit_snap_tx_api_url_detection',

          transactionOrigin,
        );

        if (respData.overall_risk_title != 'Unknown Risk') {
          contentArray.push(
            heading('Transaction Screening'),
            text(`**Overall Risk:** ${respData.overall_risk_title}`),
            text(`**Risk Overview:** ${respData.overall_risk_detail}`),
            text(`**Risk Details:** ${respData.transaction_risk_detail}`),
            divider(),
          );
        } else {
          contentArray.push(
            heading('Transaction Screening'),
            text(`**Overall Risk:** ${respData.overall_risk_title}`),
            divider(),
          );
        }

        contentArray.push(heading('URL Risk Information'));

        if (urlRespData.url_risk >= 2) {
          contentArray.push(text(`**${urlRespData.url_risk_title}**`));
        }
        contentArray.push(
          text(
            `The URL **${transactionOrigin}** has a risk of **${urlRespData.url_risk}**`,
          ),
          divider(),
        );
      

      const transactingValue = parseTransactingValue(transaction.value);
      const nativeToken = getNativeToken(chainId);

      contentArray.push(
        heading('Transfer Details'),
        text('Your Address'), text(transaction.from),
        text('Amount'), text(`${transactingValue} ${nativeToken}`),
        text('To'), text(transaction.to),
        divider(),
      );

      const content = panel(contentArray);
      return { content };
    }
  }

  // Transaction is an interaction with a smart contract because contract bytecode exists.
  const chainId = await ethereum.request({ method: 'eth_chainId' });
  // Check if chainId is undefined or null
  if (typeof chainId !== 'string') {
    const contentArray: any[] = [
      heading('HashDit Security Insights'),
      text(`Error: ChainId could not be retreived (${chainId})`),
    ];
    const content = panel(contentArray);
    return { content };
  }
  // Current chain is not supported (Not BSC and not ETH). Only perform URL screening
  if (chainId !== '0x38' && chainId !== '0x1') {

    let contentArray: any[] = [];

      const urlRespData = await getHashDitResponse(
        'hashdit_snap_tx_api_url_detection',

        transactionOrigin,
      );
      contentArray = [
        heading('URL Risk Information'),
        text(
          `The URL **${transactionOrigin}** has a risk of **${urlRespData.url_risk}**`,
        ),
        divider(),
        text(
          'HashDit Security Insights is not fully supported on this chain. Only URL screening has been performed.',
        ),
        text(
          'Currently we only support the **BSC Mainnet** and **ETH Mainnet**.',
        ),
      ];
 
    const content = panel(contentArray);
    return { content };
  } else {
    // Current chain is supported (BSC and ETH).

    let contentArray: any[] = [];

      const interactionRespData = await getHashDitResponse(
        'hashdit_snap_tx_api_transaction_request',

        transactionOrigin,
        transaction,
        chainId,
      );

      // Retrieve all addresses from the function's parameters to `targetAddresses[]`. Perform poison detection on these parameters.
      if (interactionRespData.function_name !== '') {
        let targetAddresses = [];
        // Add destination address to targets
        targetAddresses.push(transaction.to);
        // Loop through each function parameter
        for (const param of interactionRespData.function_params) {
          // Store only the values of type `address`
          if (param.type == 'address') {
            targetAddresses.push(param.value);
          }
        }
        const poisonResultArray = addressPoisoningDetection(
          accounts,
          targetAddresses,
        );
        if (poisonResultArray.length != 0) {
          contentArray = poisonResultArray;
        }
      }
      const addressRespData = await getHashDitResponse(
        'internal_address_lables_tags',

        transactionOrigin,
        transaction,
        chainId,
      );
      if (interactionRespData.overall_risk >= addressRespData.overall_risk) {
        contentArray.push(
          heading('Transaction Screening'),
          text(`**Overall Risk:** ${interactionRespData.overall_risk_title}`),
          text(`**Risk Overview:** ${interactionRespData.overall_risk_detail}`),
          text(
            `**Risk Details:** ${interactionRespData.transaction_risk_detail}`,
          ),
          divider(),
        );
      } else {
        contentArray.push(
          heading('HashDit Screening'), //todo
          text(`**Overall risk:** ${addressRespData.overall_risk_title}`),
          text(`**Risk Overview:** ${addressRespData.overall_risk_detail}`),
          text(`**Risk Details:** ${addressRespData.transaction_risk_detail}`),
          divider(),
        );
      }

      contentArray.push(heading('URL Risk Information'));

      if (interactionRespData.url_risk >= 2) {
        contentArray.push(text(`**${interactionRespData.url_risk_title}**`));
      }

      contentArray.push(
        text(
          `The URL **${transactionOrigin}** has a risk of **${interactionRespData.url_risk}**`,
        ),
        divider(),
      );

      const transactingValue = parseTransactingValue(transaction.value);
      const nativeToken = getNativeToken(chainId);

      // Only display Transfer Details if transferring more than 0 native tokens
      // This is a contract interaction. This check is necessary here because not all contract interactions transfer tokens.
      if (transactingValue > 0) {
        contentArray.push(
          heading('Transfer Details'),
          text('Your Address'), text(transaction.from),
          text('Amount'), text(`${transactingValue} ${nativeToken}`),
          text('To'), text(transaction.to),
          divider(),
        );
      }

      // Display function call insight (function names and parameters)
      if (interactionRespData.function_name !== '') {
        contentArray.push(
          heading(`Function Name: ${interactionRespData.function_name}`),
        );
        // Loop through each function parameter and display its values
        for (const param of interactionRespData.function_params) {
          contentArray.push(
            text('Name:'), text(param.name),
            text('Type:'), text(param.type),
          );
          // If the parameter is 'address' type, then we use address UI for the value
          if (param.type == 'address') {
            contentArray.push(text('Value:'), text(param.value));
          } else {
            contentArray.push(text('Value:'), text(param.value));
          }
          contentArray.push(divider());
        }
      }
    

    const content = panel(contentArray);
    return { content };
  }
};

export const onHomePage: OnHomePageHandler = async () => {
  return {
    content: panel([
      heading('HashDit Snap'),
      text(
        'Explore the power of HashDit Security and fortify your MetaMask experience. Navigate the crypto space with confidence.',
      ),
      divider(),
      heading('🔗 Links'),
      text(
        'HashDit Snap Official Website: [Hashdit](https://www.hashdit.io/en/snap)',
      ),
      text(
        'Installation Guide: [Installation](https://hashdit.gitbook.io/hashdit-snap/usage/installing-hashdit-snap)',
      ),
      text(
        'How To Use Hashdit Snap: [Usage](https://hashdit.gitbook.io/hashdit-snap/usage/how-to-use-hashdit-snap)',
      ),
      text('Documentation: [Docs](https://hashdit.gitbook.io/hashdit-snap)'),
      text(
        'FAQ/Knowledge Base: [FAQ](https://hashdit.gitbook.io/hashdit-snap/information/faq-and-knowledge-base)',
      ),
      text(
        'MetaMask Store Page: [Snap Store](https://snaps.metamask.io/snap/npm/hashdit-snap-security/)',
      ),
      divider(),
      heading('Thank you for using HashDit Snap!'),
    ]),
  };
};
