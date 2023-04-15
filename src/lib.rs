use bytes::{BufMut, Bytes, BytesMut};
use digest::Digest;
use futures::channel::oneshot;
use futures::channel::oneshot::Sender;
use futures::{select, Sink, SinkExt, Stream, StreamExt};
use signature::Signer;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use tokio::time::{sleep, Duration};

type Participants<Pk> = BTreeSet<Pk>;
type Hash<const SIZE: usize> = [u8; SIZE];

struct Block<const HASH_SIZE: usize, Tx> {
    height: u64,
    parent_hash: [u8; HASH_SIZE],
    transactions: HashSet<Tx>,
}

impl<const HASH_SIZE: usize, Tx> Block<HASH_SIZE, Tx> {
    pub fn genesis() -> Self {
        Self {
            height: 0,
            parent_hash: [0; HASH_SIZE],
            transactions: HashSet::new(),
        }
    }

    pub fn dummy(height: u64) -> Self {
        Self {
            height,
            parent_hash: [0; HASH_SIZE],
            transactions: HashSet::new(),
        }
    }

    pub fn from_transactions(
        height: u64,
        parent_hash: Hash<HASH_SIZE>,
        transactions: HashSet<Tx>,
    ) -> Self {
        Self {
            height,
            parent_hash,
            transactions,
        }
    }
}
impl<const HASH_SIZE: usize, Tx> Block<HASH_SIZE, Tx>
where
    Tx: AsRef<[u8]>,
{
    pub fn as_bytes(&self) -> Bytes {
        let mut bytes = BytesMut::new();
        bytes.put_u64(self.height);
        bytes.put_slice(&self.parent_hash);
        for tx in self.transactions.iter() {
            bytes.put_slice(tx.as_ref());
        }
        bytes.freeze()
    }
}

enum Message<const HASH_SIZE: usize, Tx> {
    Proposal(ProposalMsg<HASH_SIZE, Tx>),
    Vote(VoteMsg<HASH_SIZE>),
    Finalize(FinalizeMsg),
}

pub struct FinalizeMsg {
    height: u64,
    signature: Bytes,
}

pub struct ProposalMsg<const HASH_SIZE: usize, Tx> {
    block: Block<HASH_SIZE, Tx>,
    signature: Bytes,
}

#[derive(Eq, Hash, PartialEq)]
pub struct VoteMsg<const HASH_SIZE: usize> {
    block: [u8; HASH_SIZE],
    signature: Bytes,
}

pub struct SimplexState<const HASH_SIZE: usize, Tx, Pk> {
    height: u64,
    participants: Participants<Pk>,
    blocks: HashMap<Hash<HASH_SIZE>, Block<HASH_SIZE, Tx>>,
    votes: HashMap<Hash<HASH_SIZE>, HashSet<VoteMsg<HASH_SIZE>>>,
    finalized: HashMap<u64, HashSet<FinalizeMsg>>,
    proposals: HashMap<u64, ProposalMsg<HASH_SIZE, Tx>>,
    alpha: usize,
    threshold: usize,
}

impl<const HASH_SIZE: usize, Tx, Pk> SimplexState<HASH_SIZE, Tx, Pk> {
    pub fn new(participants: Participants<Pk>, alpha: usize) -> Self {
        let genesis = Block::genesis();
        let participants_len = participants.len();
        let mut s = Self {
            height: 0,
            participants,
            blocks: HashMap::new(),
            votes: HashMap::new(),
            finalized: HashMap::default(),
            proposals: HashMap::default(),
            alpha,
            threshold: (2 * participants_len) / 3,
        };
        s.blocks.insert(genesis.parent_hash, genesis);
        s
    }
}

pub struct Simplex<Sk, Pk> {
    sk: Sk,
    pk: Pk,
}

impl<Sk, Pk> Simplex<Sk, Pk>
where
    Sk: Signer<Bytes>,
{
    pub fn new(sk: Sk, pk: Pk) -> Self {
        Self { sk, pk }
    }

    fn vote<const HASH_SIZE: usize, Tx, D: Digest>(
        &self,
        height: u64,
        proposal: Option<&ProposalMsg<HASH_SIZE, Tx>>,
    ) -> VoteMsg<HASH_SIZE>
    where
        Tx: AsRef<[u8]>,
    {
        // TODO: validate proposal
        let block = match proposal {
            Some(ProposalMsg { block, .. }) => block.as_bytes(),
            None => Block::<HASH_SIZE, Tx>::dummy(height).as_bytes(),
        };
        let signature = self.sk.sign(&block);
        let block = D::digest(&block).to_vec().try_into().unwrap();
        VoteMsg { block, signature }
    }

    fn propose<const HASH_SIZE: usize, Tx>(
        &self,
        height: u64,
        parent: Hash<HASH_SIZE>,
        txs: HashSet<Tx>,
    ) -> ProposalMsg<HASH_SIZE, Tx>
    where
        Tx: AsRef<[u8]>,
    {
        let block = Block::<HASH_SIZE, Tx>::from_transactions(height, parent, txs);
        let block_bytes = block.as_bytes();
        let signature = self.sk.sign(&block_bytes);
        ProposalMsg { block, signature }
    }

    fn finalize(&self, height: u64) -> FinalizeMsg {
        let signature = self.sk.sign(&height.to_be_bytes());
        FinalizeMsg { height, signature }
    }

    async fn next<const HASH_SIZE: usize, Tx, Is, Os, D>(
        &self,
        state: SimplexState<HASH_SIZE, Tx, Pk>,
        mut message_stream: &mut Is,
        mut out_stream: &mut Os,
    ) -> SimplexState<HASH_SIZE, Tx, Pk>
    where
        Tx: AsRef<[u8]>,
        D: Digest,
        Is: Stream<Item = Message<HASH_SIZE, Tx>> + Unpin,
        Os: Sink<Message<HASH_SIZE, Tx>> + Clone + Unpin,
        <Os as futures::Sink<Message<HASH_SIZE, Tx>>>::Error: Debug,
    {
        let SimplexState {
            mut height,
            participants,
            mut blocks,
            mut votes,
            mut finalized,
            mut proposals,
            alpha,
            threshold,
        } = state;

        let (mut sender, receiver): (_, oneshot::Receiver<ProposalMsg<HASH_SIZE, _>>) =
            oneshot::channel();
        let mut out_stream_vote = out_stream.clone();
        let blocks_ref = &mut blocks;
        let vote = if let Some(proposal) = proposals.get(&height) {
            let vote_msg = self.vote::<HASH_SIZE, Tx, D>(height, Some(&proposal));
            Box::pin(async move {
                out_stream_vote.send(Message::Vote(vote_msg)).await.unwrap();
            }) as Pin<Box<dyn Future<Output = ()>>>
        } else {
            Box::pin(async move {
                tokio::select! {
                    Ok(proposal) = receiver => {
                        let vote_msg = self.vote::<HASH_SIZE, Tx, D>(height, Some(&proposal));
                        out_stream_vote.send(Message::Vote(vote_msg)).await.unwrap();
                        blocks_ref.insert(proposal.block.parent_hash, proposal.block);
                    },
                    _ = tokio::time::sleep(Duration::from_secs((3*alpha).try_into().unwrap())) => {
                        let vote_msg = self.vote::<HASH_SIZE, Tx, D>(height, None);
                        out_stream_vote.send(Message::Vote(vote_msg)).await.unwrap();
                        let dummy = Block::<HASH_SIZE, Tx>::dummy(height);
                        let dummy_hash = D::digest(&dummy.as_bytes()).to_vec().try_into().unwrap();
                        blocks_ref.insert(dummy_hash, dummy);
                    }
                };
            })
        };

        let proposals_ref = &mut proposals;
        let votes_ref = &mut votes;
        let finalized_ref = &mut finalized;
        let height_ref = &mut height;
        let mut sender = Some(sender);
        let process_messages = async move {
            'stop: while let Some(msg) = Box::pin(&mut message_stream).next().await {
                match msg {
                    Message::Proposal(proposal) => {
                        self.process_proposal(*height_ref, proposals_ref, &mut sender, proposal)
                            .await;
                    }
                    Message::Vote(vote) => {
                        self.process_vote(&mut out_stream, *height_ref, threshold, votes_ref, vote)
                            .await;
                    }
                    Message::Finalize(finalize) => {
                        if Self::height_is_finalized(finalized_ref, finalize.height, threshold) {
                            *height_ref = finalize.height + 1;
                            break 'stop;
                        }
                    }
                };
            }
        };

        futures::join!(vote, process_messages);

        SimplexState {
            height,
            participants,
            blocks,
            votes,
            finalized,
            proposals,
            alpha,
            threshold,
        }
    }

    pub fn block_is_notarized<const HASH_SIZE: usize>(
        votes: &HashMap<Hash<HASH_SIZE>, HashSet<VoteMsg<HASH_SIZE>>>,
        hash: &Hash<HASH_SIZE>,
        threshold: usize,
    ) -> bool {
        votes
            .get(hash)
            .map(|votes| votes.len() >= threshold)
            .unwrap_or_default()
    }

    pub fn height_is_finalized(
        finalized: &HashMap<u64, HashSet<FinalizeMsg>>,
        height: u64,
        threshold: usize,
    ) -> bool {
        finalized
            .get(&height)
            .map(|votes| votes.len() >= threshold)
            .unwrap_or_default()
    }

    async fn process_vote<const HASH_SIZE: usize, Tx, Os>(
        &self,
        out_stream: &mut Os,
        mut height: u64,
        threshold: usize,
        votes_ref: &mut HashMap<Hash<HASH_SIZE>, HashSet<VoteMsg<HASH_SIZE>>>,
        vote: VoteMsg<HASH_SIZE>,
    ) where
        Os: Sink<Message<HASH_SIZE, Tx>> + Unpin,
        <Os as futures::Sink<Message<HASH_SIZE, Tx>>>::Error: Debug,
    {
        let block = vote.block;
        let votes = votes_ref.entry(block).or_insert_with(HashSet::new);
        votes.insert(vote);
        if Self::block_is_notarized(votes_ref, &block, threshold) {
            let finalize = self.finalize(height);
            out_stream.send(Message::Finalize(finalize)).await.unwrap();
        }
    }

    async fn process_proposal<const HASH_SIZE: usize, Tx>(
        &self,
        height: u64,
        proposals_ref: &mut HashMap<u64, ProposalMsg<HASH_SIZE, Tx>>,
        sender: &mut Option<Sender<ProposalMsg<HASH_SIZE, Tx>>>,
        proposal: ProposalMsg<HASH_SIZE, Tx>,
    ) where
        Tx: AsRef<[u8]>,
    {
        if proposal.block.height == height {
            if sender.is_none() {
                return;
            }
            if let Err(e) = sender.take().unwrap().send(proposal) {
                eprintln!("Failed to send proposal for height: {:?}", e.block.height);
            }
        } else {
            // just store the first seen proposal for each height
            let _ = proposals_ref
                .entry(proposal.block.height)
                .or_insert(proposal);
        }
    }
}
