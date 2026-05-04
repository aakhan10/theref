import { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import "./Home.css";

export default function Home() {
  const { user, accessToken, logout } = useAuth();

  const [posts, setPosts] = useState([]);
  const [replyingTo, setReplyingTo] = useState(null);
  const [replyText, setReplyText] = useState("");
  const [selectedSport, setSelectedSport] = useState("All");

  useEffect(() => {
    async function loadPosts() {
      try {
        const res = await fetch("http://localhost:8080/posts");
        const data = await res.json();

        const formatted = data.map((post) => ({
          id: post.id,
          author: post.sport || "TheRef",
          title: post.title,
          body: post.description,
          video_url: post.video_url,
          thumbnail_url: post.thumbnail_url,
          /*likes: 0,
          userLiked: false,
          upvotes: Number(post.likes || 0),
          downvotes: Number(post.dislikes || 0),
          userVote: null,
          */
          likes: 2506,
          userLiked: false,
          upvotes: 420,
          downvotes: 1208,
          userVote: null,
          comments: (post.comments || []).map((comment) => ({
            id: comment.id,
            text: comment.text,
            parent_comment_id: comment.parent_comment_id,
            user_email: comment.user_email,
            username: comment.username,
            isEditing: false,
          })),
          newComment: "",
        }));

        setPosts(formatted);
      } catch (err) {
        console.error("Failed to load posts:", err);
      }
    }

    loadPosts();
  }, []);

  const getDisplayName = (comment) => {
    return comment.username || comment.user_email?.split("@")[0] || "Anonymous";
  };

  const handleLike = (id) => {
    setPosts((prev) =>
      prev.map((post) => {
        if (post.id !== id) return post;

        if (post.userLiked) {
          return {
            ...post,
            likes: post.likes - 1,
            userLiked: false,
          };
        }

        return {
          ...post,
          likes: post.likes + 1,
          userLiked: true,
        };
      })
    );
  };

  const handleVote = (id, type) => {
    setPosts((prev) =>
      prev.map((post) => {
        if (post.id !== id) return post;

        let { upvotes, downvotes, userVote } = post;

        if (userVote === "up") upvotes--;
        if (userVote === "down") downvotes--;

        if (userVote === type) {
          return {
            ...post,
            upvotes,
            downvotes,
            userVote: null,
          };
        }

        if (type === "up") upvotes++;
        if (type === "down") downvotes++;

        return {
          ...post,
          upvotes,
          downvotes,
          userVote: type,
        };
      })
    );
  };

  const handleCommentChange = (postId, value) => {
    setPosts((prev) =>
      prev.map((post) =>
        post.id === postId ? { ...post, newComment: value } : post
      )
    );
  };

  const handleAddComment = async (postId) => {
    const post = posts.find((p) => p.id === postId);
    if (!post) return;

    const trimmed = post.newComment.trim();
    if (!trimmed) return;

    try {
      const res = await fetch("http://localhost:8080/comments", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          post_id: postId,
          body: trimmed,
          parent_comment_id: null,
        }),
      });

      if (!res.ok) throw new Error("Failed to save comment");

      const savedComment = await res.json();

      setPosts((prev) =>
        prev.map((post) =>
          post.id === postId
            ? {
                ...post,
                comments: [
                  ...post.comments,
                  {
                    id: savedComment.id,
                    text: savedComment.body,
                    parent_comment_id: savedComment.parent_comment_id,
                    user_email: user?.email,
                    username: user?.username || user?.email?.split("@")[0],
                    isEditing: false,
                  },
                ],
                newComment: "",
              }
            : post
        )
      );
    } catch (err) {
      console.error("Failed to save comment:", err);
    }
  };

  const handleAddReply = async (postId, parentCommentId) => {
    const trimmed = replyText.trim();
    if (!trimmed) return;

    try {
      const res = await fetch("http://localhost:8080/comments", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          post_id: postId,
          body: trimmed,
          parent_comment_id: parentCommentId,
        }),
      });

      if (!res.ok) throw new Error("Failed to save reply");

      const savedReply = await res.json();

      setPosts((prev) =>
        prev.map((post) =>
          post.id === postId
            ? {
                ...post,
                comments: [
                  ...post.comments,
                  {
                    id: savedReply.id,
                    text: savedReply.body,
                    parent_comment_id: savedReply.parent_comment_id,
                    user_email: user?.email,
                    username: user?.username || user?.email?.split("@")[0],
                    isEditing: false,
                  },
                ],
              }
            : post
        )
      );

      setReplyingTo(null);
      setReplyText("");
    } catch (err) {
      console.error("Failed to save reply:", err);
    }
  };

  const handleCommentKeyDown = (e, postId) => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleAddComment(postId);
    }
  };

  const handleDeleteComment = async (postId, commentId) => {
    try {
      const res = await fetch(`http://localhost:8080/comments/${commentId}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      if (!res.ok) throw new Error("Failed to delete comment");

      setPosts((prev) =>
        prev.map((post) =>
          post.id === postId
            ? {
                ...post,
                comments: post.comments.filter(
                  (comment) =>
                    comment.id !== commentId &&
                    comment.parent_comment_id !== commentId
                ),
              }
            : post
        )
      );
    } catch (err) {
      console.error("Failed to delete comment:", err);
    }
  };

  const handleEditComment = (postId, commentId) => {
    setPosts((prev) =>
      prev.map((post) => {
        if (post.id !== postId) return post;

        return {
          ...post,
          comments: post.comments.map((comment) =>
            comment.id === commentId
              ? { ...comment, isEditing: true }
              : comment
          ),
        };
      })
    );
  };

  const handleEditCommentChange = (postId, commentId, value) => {
    setPosts((prev) =>
      prev.map((post) => {
        if (post.id !== postId) return post;

        return {
          ...post,
          comments: post.comments.map((comment) =>
            comment.id === commentId ? { ...comment, text: value } : comment
          ),
        };
      })
    );
  };

  const handleSaveComment = (postId, commentId) => {
    setPosts((prev) =>
      prev.map((post) => {
        if (post.id !== postId) return post;

        return {
          ...post,
          comments: post.comments.map((comment) => {
            if (comment.id !== commentId) return comment;

            return {
              ...comment,
              text: comment.text.trim(),
              isEditing: false,
            };
          }),
        };
      })
    );
  };

  const handleEditKeyDown = (e, postId, commentId) => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleSaveComment(postId, commentId);
    }
  };

  return (
    <div className="home-page">
      <header className="topbar">
      <div className="brand-center">
        <div className="logo-mark">TR</div>
        <h1 className="logo">The Ref</h1>
        <p className="tagline">Debate. Vote. Settle the call.</p>
      </div>

        <div className="topbar-right">
          <span className="welcome-text">
            {user?.email ? `Signed in as ${user.email}` : "Welcome"}
          </span>
          <button className="logout-btn" onClick={logout}>
            Log out
          </button>
        </div>
      </header>

      <main className="feed-layout">
      <aside className="left-panel">
        <div className="profile-card">
          <h3>Your Profile</h3>

          <div className="info-box">
            <span className="label">Email</span>
            <span className="value">{user?.email}</span>
          </div>

          <div className="info-box">
            <span className="label">Role</span>
            <span className="value">{user?.role}</span>
          </div>
        </div>

        <div className="sports-nav">
          <h3>Sports</h3>

          <button onClick={() => setSelectedSport("All")}>📈 Trending</button>
          <button onClick={() => setSelectedSport("Football")}>🏈 Football</button>
          <button onClick={() => setSelectedSport("Basketball")}>🏀 Basketball</button>
          <button onClick={() => setSelectedSport("Baseball")}>⚾ Baseball</button>
          <button onClick={() => setSelectedSport("Soccer")}>⚽ Soccer</button>
        </div>
      </aside>
        <section className="feed-section">
          <div className="hero-card">
            <h2>Trending Debates</h2>
            <p>Vote and comment on controversial sports moments.</p>
          </div>

          <div className="posts-list">
          {posts
              .filter((post) =>
                selectedSport === "All" ? true : post.author === selectedSport
              )
              .map((post) => {
              const totalVotes = post.upvotes + post.downvotes;
              const upPercent =
                totalVotes === 0
                  ? 0
                  : Math.round((post.upvotes / totalVotes) * 100);
              const downPercent =
                totalVotes === 0
                  ? 0
                  : Math.round((post.downvotes / totalVotes) * 100);

              const parentComments = post.comments.filter(
                (comment) => !comment.parent_comment_id
              );

              const getReplies = (commentId) =>
                post.comments.filter(
                  (comment) => comment.parent_comment_id === commentId
                );

              return (
                <article className="post-card" key={post.id}>
                  <h3>{post.title}</h3>
                  <p className="post-author">@{post.author}</p>
                  <p className="post-body">{post.body}</p>

                  {post.video_url && (
                    <a
                      href={post.video_url}
                      target="_blank"
                      rel="noreferrer"
                      className="post-media-link"
                    >
                      <img
                        src={post.thumbnail_url || "/placeholder-play.jpg"}
                        alt={post.title}
                        className="post-image"
                      />
                      <p className="watch-link">▶ Watch the play</p>
                    </a>
                  )}

                  <div className="post-actions">
                    <button
                      className={`action-btn ${
                        post.userVote === "up" ? "active" : ""
                      }`}
                      onClick={() => handleVote(post.id, "up")}
                    >
                      👍 {post.upvotes}
                    </button>

                    <button
                      className={`action-btn ${
                        post.userVote === "down" ? "active" : ""
                      }`}
                      onClick={() => handleVote(post.id, "down")}
                    >
                      👎 {post.downvotes}
                    </button>

                    <button
                      className={`action-btn ${
                        post.userLiked ? "active" : ""
                      }`}
                      onClick={() => handleLike(post.id)}
                    >
                      ❤️ {post.likes}
                    </button>
                  </div>

                  <div className="vote-summary">
                    <p className="vote-total">Total voters: {totalVotes}</p>

                    <div className="vote-percentages">
                      <span>👍 {upPercent}% liked the call</span>
                      <span>👎 {downPercent}% disliked the call</span>
                    </div>

                    <div className="vote-bar">
                      <div
                        className="vote-bar-up"
                        style={{ width: `${upPercent}%` }}
                      ></div>
                      <div
                        className="vote-bar-down"
                        style={{ width: `${downPercent}%` }}
                      ></div>
                    </div>
                  </div>

                  <div className="comments-section">
                    <h4>Comments</h4>

                    {parentComments.map((comment) => (
                      <div key={comment.id} className="comment">
                        {comment.isEditing ? (
                          <div className="comment-edit-row">
                            <input
                              type="text"
                              value={comment.text}
                              onChange={(e) =>
                                handleEditCommentChange(
                                  post.id,
                                  comment.id,
                                  e.target.value
                                )
                              }
                              onKeyDown={(e) =>
                                handleEditKeyDown(e, post.id, comment.id)
                              }
                            />
                            <button
                              className="comment-action-btn save-btn"
                              onClick={() =>
                                handleSaveComment(post.id, comment.id)
                              }
                            >
                              Save
                            </button>
                          </div>
                        ) : (
                          <div className="comment-row">
                            <div className="comment-content">
                              <strong className="comment-user">
                                {getDisplayName(comment)}:{" "}
                              </strong>
                              <span className="comment-text">
                                {comment.text}
                              </span>
                            </div>

                            <div className="comment-actions">
                              <button
                                className="comment-action-btn"
                                onClick={() => setReplyingTo(comment.id)}
                              >
                                Reply
                              </button>

                              <button
                                className="comment-action-btn"
                                onClick={() =>
                                  handleEditComment(post.id, comment.id)
                                }
                              >
                                Edit
                              </button>

                              <button
                                className="comment-action-btn delete-btn"
                                onClick={() =>
                                  handleDeleteComment(post.id, comment.id)
                                }
                              >
                                Delete
                              </button>
                            </div>
                          </div>
                        )}

                        {replyingTo === comment.id && (
                          <div className="reply-input">
                            <input
                              type="text"
                              placeholder="Write a reply..."
                              value={replyText}
                              onChange={(e) => setReplyText(e.target.value)}
                              onKeyDown={(e) => {
                                if (e.key === "Enter") {
                                  e.preventDefault();
                                  handleAddReply(post.id, comment.id);
                                }
                              }}
                            />
                            <button
                              onClick={() =>
                                handleAddReply(post.id, comment.id)
                              }
                            >
                              Reply
                            </button>
                          </div>
                        )}

                        {getReplies(comment.id).map((reply) => (
                          <div key={reply.id} className="comment reply-comment">
                            <div className="comment-row">
                              <div className="comment-content">
                                <strong className="comment-user">
                                  {getDisplayName(reply)}:{" "}
                                </strong>
                                <span className="comment-text">
                                  {reply.text}
                                </span>
                              </div>

                              <div className="comment-actions">
                                <button
                                  className="comment-action-btn delete-btn"
                                  onClick={() =>
                                    handleDeleteComment(post.id, reply.id)
                                  }
                                >
                                  Delete
                                </button>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    ))}

                    <div className="comment-input">
                      <input
                        type="text"
                        placeholder="Write a comment..."
                        value={post.newComment}
                        onChange={(e) =>
                          handleCommentChange(post.id, e.target.value)
                        }
                        onKeyDown={(e) => handleCommentKeyDown(e, post.id)}
                      />
                      <button onClick={() => handleAddComment(post.id)}>
                        Post
                      </button>
                    </div>
                  </div>
                </article>
              );
            })}
          </div>
        </section>
      </main>
    </div>
  );
}