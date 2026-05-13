import { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import "./Home.css";

export default function Home() {
  const { user, accessToken, logout } = useAuth();

  const [posts, setPosts] = useState([]);
  const [replyingTo, setReplyingTo] = useState(null);
  const [replyText, setReplyText] = useState("");
  const [selectedSport, setSelectedSport] = useState("All");
  const [showAddPost, setShowAddPost] = useState(false);
  const [searchTerm, setSearchTerm] = useState("");

  const [newPost, setNewPost] = useState({
    title: "",
    sport: "",
    description: "",
    video_url: "",
    thumbnail_url: "",
  });

  const canAddPost = user?.role === "admin" || user?.role === "moderator";

  useEffect(() => {
    async function loadPosts() {
      try {
        const headers = accessToken
          ? { Authorization: `Bearer ${accessToken}` }
          : {};

        const res = await fetch("http://localhost:8080/posts", {
          headers,
        });

        const data = await res.json();

        const formatted = data.map((post) => ({
          id: post.id,
          author: post.sport || "TheRef",
          title: post.title,
          body: post.description,
          video_url: post.video_url,
          thumbnail_url: post.thumbnail_url,

          likes: Number(post.heart_likes || 0),
          userLiked: Boolean(post.user_liked),

          upvotes: Number(post.upvotes || 0),
          downvotes: Number(post.downvotes || 0),
          userVote:
            Number(post.user_vote) === 1
              ? "up"
              : Number(post.user_vote) === -1
              ? "down"
              : null,

          comments: (post.comments || []).map((comment) => ({
            id: comment.id,
            text: comment.text,
            parent_comment_id: comment.parent_comment_id,
            user_id: comment.user_id,
            user_email: comment.user_email,
            username: comment.username,
            likes: Number(comment.likes || 0),
            userLiked: Boolean(comment.user_liked),
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
  }, [accessToken]);

  const getDisplayName = (comment) => {
    return comment.username || comment.user_email?.split("@")[0] || "Anonymous";
  };

  const canDeleteComment = (comment) => {
    return user?.role === "admin" || String(comment.user_id) === String(user?.id);
  };

  const canEditComment = (comment) => {
    return String(comment.user_id) === String(user?.id);
  };

  const handleLike = async (id) => {
    if (!accessToken) {
      alert("You must be logged in to like a post.");
      return;
    }

    try {
      const res = await fetch("http://localhost:8080/likes", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          post_id: id,
        }),
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || "Failed to save like");
      }

      const data = await res.json();

      setPosts((prev) =>
        prev.map((post) =>
          post.id === id
            ? {
                ...post,
                likes: data.likes,
                userLiked: data.userLiked,
              }
            : post
        )
      );
    } catch (err) {
      console.error("Failed to save like:", err);
      alert(err.message);
    }
  };

  const handleVote = async (id, type) => {
    const value = type === "up" ? 1 : -1;

    if (!accessToken) {
      alert("You must be logged in to vote.");
      return;
    }

    try {
      const res = await fetch("http://localhost:8080/votes", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          post_id: id,
          value,
        }),
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || "Failed to save vote");
      }

      const data = await res.json();

      setPosts((prev) =>
        prev.map((post) =>
          post.id === id
            ? {
                ...post,
                upvotes: data.upvotes,
                downvotes: data.downvotes,
                userVote: data.userVote,
              }
            : post
        )
      );
    } catch (err) {
      console.error("Failed to save vote:", err);
      alert(err.message);
    }
  };

  const handleLikeComment = async (postId, commentId) => {
    if (!accessToken) {
      alert("You must be logged in to like a comment.");
      return;
    }

    try {
      const res = await fetch("http://localhost:8080/comment-likes", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          comment_id: commentId,
        }),
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || "Failed to like comment");
      }

      const data = await res.json();

      setPosts((prev) =>
        prev.map((post) =>
          post.id === postId
            ? {
                ...post,
                comments: post.comments.map((comment) =>
                  String(comment.id) === String(commentId)
                    ? {
                        ...comment,
                        likes: data.likes,
                        userLiked: data.userLiked,
                      }
                    : comment
                ),
              }
            : post
        )
      );
    } catch (err) {
      console.error("Failed to like comment:", err);
      alert(err.message);
    }
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

    if (!accessToken) {
      alert("You must be logged in to comment.");
      return;
    }

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
                    user_id: user?.id,
                    user_email: user?.email,
                    username: user?.username || user?.email?.split("@")[0],
                    likes: 0,
                    userLiked: false,
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
      alert(err.message);
    }
  };

  const handleAddReply = async (postId, parentCommentId) => {
    const trimmed = replyText.trim();
    if (!trimmed) return;

    if (!accessToken) {
      alert("You must be logged in to reply.");
      return;
    }

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
                    user_id: user?.id,
                    user_email: user?.email,
                    username: user?.username || user?.email?.split("@")[0],
                    likes: 0,
                    userLiked: false,
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
      alert(err.message);
    }
  };

  const handleCommentKeyDown = (e, postId) => {
    if (e.key === "Enter") {
      e.preventDefault();
      handleAddComment(postId);
    }
  };

  const handleDeleteComment = async (postId, commentId) => {
    if (!accessToken) {
      alert("You must be logged in to delete a comment.");
      return;
    }

    try {
      const res = await fetch(`http://localhost:8080/comments/${commentId}`, {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || "Failed to delete comment");
      }

      setPosts((prev) =>
        prev.map((post) =>
          post.id === postId
            ? {
                ...post,
                comments: post.comments.filter(
                  (comment) =>
                    String(comment.id) !== String(commentId) &&
                    String(comment.parent_comment_id) !== String(commentId)
                ),
              }
            : post
        )
      );
    } catch (err) {
      console.error("Failed to delete comment:", err);
      alert(err.message);
    }
  };

  const handleEditComment = (postId, commentId) => {
    setPosts((prev) =>
      prev.map((post) => {
        if (post.id !== postId) return post;

        return {
          ...post,
          comments: post.comments.map((comment) =>
            String(comment.id) === String(commentId)
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
            String(comment.id) === String(commentId)
              ? { ...comment, text: value }
              : comment
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
            if (String(comment.id) !== String(commentId)) return comment;

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

  const handleNewPostChange = (e) => {
    const { name, value } = e.target;

    setNewPost((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  const handleCreatePost = async (e) => {
    e.preventDefault();

    const trimmedTitle = newPost.title.trim();
    const trimmedDescription = newPost.description.trim();

    if (!trimmedTitle || !newPost.sport || !trimmedDescription) {
      return;
    }

    if (!accessToken) {
      alert("You must be logged in to create a post.");
      return;
    }

    try {
      const res = await fetch("http://localhost:8080/posts", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify({
          title: trimmedTitle,
          sport: newPost.sport,
          description: trimmedDescription,
          video_url: newPost.video_url.trim() || null,
          thumbnail_url: newPost.thumbnail_url.trim() || null,
        }),
      });

      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(errorData.error || "Failed to create post");
      }

      const savedPost = await res.json();

      const formattedPost = {
        id: savedPost.id,
        author: savedPost.sport || "TheRef",
        title: savedPost.title,
        body: savedPost.description,
        video_url: savedPost.video_url,
        thumbnail_url: savedPost.thumbnail_url,
        likes: 0,
        userLiked: false,
        upvotes: 0,
        downvotes: 0,
        userVote: null,
        comments: [],
        newComment: "",
      };

      setPosts((prev) => [formattedPost, ...prev]);

      setNewPost({
        title: "",
        sport: "",
        description: "",
        video_url: "",
        thumbnail_url: "",
      });

      setShowAddPost(false);
    } catch (err) {
      console.error("Failed to create post:", err);
      alert(err.message);
    }
  };

  const filteredPosts = posts.filter((post) => {
    const matchesSport =
      selectedSport === "All" ? true : post.author === selectedSport;

    const search = searchTerm.toLowerCase().trim();

    const matchesSearch =
      search === "" ||
      post.title?.toLowerCase().includes(search) ||
      post.body?.toLowerCase().includes(search) ||
      post.author?.toLowerCase().includes(search) ||
      post.comments?.some((comment) =>
        comment.text?.toLowerCase().includes(search)
      );

    return matchesSport && matchesSearch;
  });

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

          {canAddPost && (
            <button
              className="add-post-btn"
              onClick={() => setShowAddPost((prev) => !prev)}
            >
              {showAddPost ? "Cancel" : "+ Add Post"}
            </button>
          )}

          {canAddPost && showAddPost && (
            <form className="add-post-form" onSubmit={handleCreatePost}>
              <h3>Add New Debate</h3>

              <input
                type="text"
                name="title"
                placeholder="Title"
                value={newPost.title}
                onChange={handleNewPostChange}
                required
              />

              <select
                name="sport"
                value={newPost.sport}
                onChange={handleNewPostChange}
                required
              >
                <option value="">Select a sport</option>
                <option value="Football">Football</option>
                <option value="Basketball">Basketball</option>
                <option value="Baseball">Baseball</option>
                <option value="Soccer">Soccer</option>
              </select>

              <textarea
                name="description"
                placeholder="Describe the controversial call..."
                value={newPost.description}
                onChange={handleNewPostChange}
                required
              />

              <input
                type="url"
                name="video_url"
                placeholder="Video URL"
                value={newPost.video_url}
                onChange={handleNewPostChange}
              />

              <input
                type="url"
                name="thumbnail_url"
                placeholder="Thumbnail image URL"
                value={newPost.thumbnail_url}
                onChange={handleNewPostChange}
              />

              <button type="submit" className="submit-post-btn">
                Create Post
              </button>
            </form>
          )}

          <div className="sports-nav">
            <h3>Sports</h3>

            <button onClick={() => setSelectedSport("All")}>
              📈 Trending
            </button>
            <button onClick={() => setSelectedSport("Football")}>
              🏈 Football
            </button>
            <button onClick={() => setSelectedSport("Basketball")}>
              🏀 Basketball
            </button>
            <button onClick={() => setSelectedSport("Baseball")}>
              ⚾ Baseball
            </button>
            <button onClick={() => setSelectedSport("Soccer")}>
              ⚽ Soccer
            </button>
          </div>
        </aside>

        <section className="feed-section">
          <div className="hero-card">
            <h2>Trending Debates</h2>
            <p>Vote and comment on controversial sports moments.</p>
          </div>

          <div className="search-card">
            <input
              type="text"
              placeholder="Search debates, sports, or comments..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="search-input"
            />

            {searchTerm && (
              <button
                className="clear-search-btn"
                onClick={() => setSearchTerm("")}
              >
                Clear
              </button>
            )}
          </div>

          <div className="posts-list">
            {filteredPosts.length === 0 && (
              <div className="no-results-card">
                <h3>No debates found</h3>
                <p>Try searching for another sport, team, or keyword.</p>
              </div>
            )}

            {filteredPosts.map((post) => {
              const totalVotes = post.upvotes + post.downvotes;
              const upPercent =
                totalVotes === 0
                  ? 0
                  : Math.round((post.upvotes / totalVotes) * 100);
              const downPercent =
                totalVotes === 0
                  ? 0
                  : Math.round((post.downvotes / totalVotes) * 100);

              const parentComments = (post.comments || []).filter(
                (comment) => !comment.parent_comment_id
              );

              const getReplies = (commentId) =>
                (post.comments || []).filter(
                  (comment) =>
                    String(comment.parent_comment_id) === String(commentId)
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
                                className={`comment-action-btn ${
                                  comment.userLiked ? "active" : ""
                                }`}
                                onClick={() =>
                                  handleLikeComment(post.id, comment.id)
                                }
                              >
                                ❤️ {comment.likes}
                              </button>

                              <button
                                className="comment-action-btn"
                                onClick={() => setReplyingTo(comment.id)}
                              >
                                Reply
                              </button>

                              {canEditComment(comment) && (
                                <button
                                  className="comment-action-btn"
                                  onClick={() =>
                                    handleEditComment(post.id, comment.id)
                                  }
                                >
                                  Edit
                                </button>
                              )}

                              {canDeleteComment(comment) && (
                                <button
                                  className="comment-action-btn delete-btn"
                                  onClick={() =>
                                    handleDeleteComment(post.id, comment.id)
                                  }
                                >
                                  Delete
                                </button>
                              )}
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
                          <div
                            key={reply.id}
                            className="comment reply-comment"
                          >
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
                                  className={`comment-action-btn ${
                                    reply.userLiked ? "active" : ""
                                  }`}
                                  onClick={() =>
                                    handleLikeComment(post.id, reply.id)
                                  }
                                >
                                  ❤️ {reply.likes}
                                </button>

                                {canDeleteComment(reply) && (
                                  <button
                                    className="comment-action-btn delete-btn"
                                    onClick={() =>
                                      handleDeleteComment(post.id, reply.id)
                                    }
                                  >
                                    Delete
                                  </button>
                                )}
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